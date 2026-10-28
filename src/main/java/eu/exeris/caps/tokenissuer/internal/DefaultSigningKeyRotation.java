package eu.exeris.caps.tokenissuer.internal;

import eu.exeris.caps.tokenissuer.api.KeyState;
import eu.exeris.caps.tokenissuer.api.SigningKeyInfo;
import eu.exeris.caps.tokenissuer.api.SigningKeyRotation;
import eu.exeris.caps.tokenissuer.api.TokenIssuerConfig;
import eu.exeris.caps.tokenissuer.api.exception.KeyRotationException;
import eu.exeris.caps.tokenissuer.api.exception.NoActiveKeyException;
import eu.exeris.caps.tokenissuer.api.exception.TokenIssuerException;
import eu.exeris.caps.tokenissuer.internal.audit.TokenIssuerAuditBridge;
import eu.exeris.caps.tokenissuer.internal.crypto.Ed25519Signer;
import eu.exeris.caps.tokenissuer.internal.crypto.Rfc8037JwksBuilder;
import eu.exeris.caps.tokenissuer.internal.repository.SigningKeyRecord;
import eu.exeris.caps.tokenissuer.internal.repository.SigningKeyRepository;
import eu.exeris.kernel.spi.scheduling.JobDescriptor;
import eu.exeris.kernel.spi.scheduling.JobHandle;
import eu.exeris.kernel.spi.scheduling.JobScheduler;
import eu.exeris.kernel.spi.scheduling.JobTrigger;

import java.security.KeyPair;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * Default implementation of {@link SigningKeyRotation}.
 *
 * <p>A key signs for {@link TokenIssuerConfig#keyTtl()}. When it is replaced it becomes
 * {@link KeyState#RETIRING} with {@code retiredAt = now + maxTokenTtl + clockSkew}: the last token
 * it signed cannot be accepted by any verifier after that instant, so the key stays in the JWKS
 * exactly until then. Every instant comes from the injected {@link Clock}.
 *
 * <p><b>Lock order.</b> Two locks exist and they are always taken in this order: first the
 * repository's cluster lock ({@link SigningKeyRepository#rotateUnderClusterLock}), then the
 * {@code rotationMonitor} inside it. No public method is {@code synchronized}, and nothing calls the
 * cluster lock while holding the monitor, so a thread that waits for the cluster lock never owns the
 * monitor another thread needs. {@code scheduleLock} guards only the job handle and is a leaf: no
 * other lock is requested while it is held.
 *
 * @since 0.1.0
 */
public final class DefaultSigningKeyRotation implements SigningKeyRotation {

    private static final System.Logger LOG = System.getLogger(DefaultSigningKeyRotation.class.getName());

    static final String ROTATION_JOB_NAME = "exeris-token-issuer-key-rotation";

    private final SigningKeyRepository repository;
    private final TokenIssuerConfig config;
    private final TokenIssuerAuditBridge auditBridge;
    private final JobScheduler jobScheduler;
    private final Clock clock;
    private final Object rotationMonitor = new Object();
    private final Object scheduleLock = new Object();
    private JobHandle rotationJobHandle;

    public DefaultSigningKeyRotation(
            SigningKeyRepository repository,
            TokenIssuerConfig config,
            TokenIssuerAuditBridge auditBridge,
            JobScheduler jobScheduler,
            Clock clock
    ) {
        this.repository = Objects.requireNonNull(repository, "repository must not be null");
        this.config = Objects.requireNonNull(config, "config must not be null");
        this.auditBridge = auditBridge;
        this.jobScheduler = jobScheduler;
        this.clock = Objects.requireNonNull(clock, "clock must not be null");
    }

    public void startScheduledRotation() {
        synchronized (scheduleLock) {
            if (jobScheduler != null && rotationJobHandle == null) {
                JobDescriptor descriptor = new JobDescriptor(
                        ROTATION_JOB_NAME,
                        new JobTrigger.FixedInterval(config.rotationCheckInterval(), config.rotationCheckInterval()),
                        this::runScheduledCycle
                );
                this.rotationJobHandle = jobScheduler.submit(descriptor);
            }
        }
    }

    public void stopScheduledRotation() {
        synchronized (scheduleLock) {
            if (rotationJobHandle != null) {
                rotationJobHandle.cancel();
                rotationJobHandle = null;
            }
        }
    }

    /**
     * A failing cycle must not cancel the schedule: it is logged and the next cycle retries, and
     * {@link #runMaintenanceCycle()} leaves the repository consistent at every step.
     */
    private void runScheduledCycle() {
        try {
            runMaintenanceCycle();
        } catch (RuntimeException e) {
            LOG.log(System.Logger.Level.WARNING, "signing key maintenance cycle failed; retrying next cycle", e);
        }
    }

    /**
     * One maintenance cycle: advance the key lifecycle, retire keys past their publication window,
     * and delete the private key material of retired keys. A successor that is still inside its
     * publication lead is not an error of the cycle; retirement and deletion run regardless.
     */
    void runMaintenanceCycle() {
        try {
            rotateIfDue();
        } catch (NoActiveKeyException e) {
            LOG.log(System.Logger.Level.INFO, e.getMessage());
        }
        retireExpiredKeys();
        repository.deleteRetiredBefore(clock.instant());
    }

    public SigningKeyInfo ensureActiveKey() {
        return rotateIfDue();
    }

    @Override
    public SigningKeyInfo rotateIfDue() {
        SigningKeyInfo result = advance(false);
        if (result.state() != KeyState.ACTIVE) {
            // Raised after the cluster lock is released: throwing inside it would roll back the
            // pending key that was just stored, and it would never mature.
            throw new NoActiveKeyException("No unexpired active signing key: the next key " + result.kid()
                    + " is published and becomes active at " + activationInstant(result, false));
        }
        return result;
    }

    @Override
    public SigningKeyInfo rotateKeys() {
        return advance(true);
    }

    @Override
    public void withdrawKey(String kid) {
        Objects.requireNonNull(kid, "kid must not be null");
        List<Runnable> auditEvents = new ArrayList<>();
        repository.rotateUnderClusterLock(() -> {
            auditEvents.clear();
            synchronized (rotationMonitor) {
                try {
                    withdrawLocked(kid, auditEvents);
                    return null;
                } catch (TokenIssuerException | IllegalArgumentException e) {
                    throw e;
                } catch (RuntimeException e) {
                    throw new KeyRotationException("Failed to withdraw signing key " + kid, e);
                }
            }
        });
        auditEvents.forEach(Runnable::run);
    }

    private void withdrawLocked(String kid, List<Runnable> auditEvents) {
        Instant now = clock.instant();
        List<SigningKeyInfo> all = repository.findAllInfo();
        SigningKeyInfo target = all.stream().filter(k -> k.kid().equals(kid)).findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Unknown signing key: " + kid));

        Instant retiredAt = target.retiredAt() != null && target.retiredAt().isBefore(now) ? target.retiredAt() : now;
        repository.updateState(kid, KeyState.RETIRED, retiredAt);
        if (auditBridge != null) {
            auditEvents.add(() -> auditBridge.logKeyWithdrawn(kid));
        }

        if (target.state() == KeyState.ACTIVE) {
            List<SigningKeyInfo> pending = all.stream()
                    .filter(k -> k.state() == KeyState.PENDING && !k.kid().equals(kid))
                    .toList();
            SigningKeyInfo ready = retireExpiredPendingAndFindReady(pending, now, false);
            if (ready != null) {
                retireSurplusPending(pending, ready, now);
                repository.updateState(ready.kid(), KeyState.ACTIVE, null);
                if (auditBridge != null) {
                    auditEvents.add(() -> auditBridge.logKeyRotated(ready.kid(), kid));
                }
            } else {
                List<SigningKeyInfo> waiting = pending.stream().filter(k -> now.isBefore(k.expiresAt())).toList();
                if (waiting.isEmpty()) {
                    createPendingKey(now, auditEvents);
                }
            }
        }
    }

    /**
     * The instant a pending key may start to sign: the later of its planned activation (its expiry
     * minus one signing period) and the end of the JWKS cache lifetime after its publication.
     */
    private Instant activationInstant(SigningKeyInfo pending) {
        return activationInstant(pending, false);
    }

    private Instant activationInstant(SigningKeyInfo pending, boolean hasValidActiveKey) {
        Instant published = pending.createdAt().plus(config.jwksMaxAge());
        if (!hasValidActiveKey) {
            return published;
        }
        Instant planned = pending.expiresAt().minus(config.keyTtl());
        return planned.isAfter(published) ? planned : published;
    }

    /**
     * Advances the lifecycle under the repository's cluster lock, then the in-process monitor (see
     * the class comment for the lock order). Only metadata is read: no private key is unsealed to
     * decide what to do. Audit events are collected while the lock is held and emitted after it
     * returns, so a rolled-back transaction never leaves an event for a key that was not stored.
     *
     * <ol>
     *   <li>A pending key whose activation instant has passed becomes ACTIVE and every other ACTIVE
     *       key becomes RETIRING until {@code now + publicationOverlap}. A pending key that expired
     *       before it could activate never signed and is retired at once.</li>
     *   <li>While the active key is valid, its successor is generated as PENDING once
     *       {@code publicationLead} remains before it expires.</li>
     *   <li>With no active key and no pending key, no verifier has trusted a key of this issuer, and
     *       the first key is ACTIVE immediately.</li>
     *   <li>Otherwise the active key has expired and the successor is not yet old enough: a pending
     *       key is created if none exists and is returned.</li>
     * </ol>
     *
     * @param forced start a rotation although the active key is not due
     */
    private SigningKeyInfo advance(boolean forced) {
        List<Runnable> auditEvents = new ArrayList<>();
        SigningKeyInfo result = repository.rotateUnderClusterLock(() -> {
            auditEvents.clear();
            synchronized (rotationMonitor) {
                try {
                    return advanceLocked(forced, auditEvents);
                } catch (TokenIssuerException e) {
                    throw e;
                } catch (RuntimeException e) {
                    throw new KeyRotationException("Failed to rotate signing keys", e);
                }
            }
        });
        auditEvents.forEach(Runnable::run);
        return result;
    }

    private SigningKeyInfo advanceLocked(boolean forced, List<Runnable> auditEvents) {
        Instant now = clock.instant();
        List<SigningKeyInfo> all = repository.findAllInfo();
        SigningKeyInfo active = all.stream().filter(k -> k.state() == KeyState.ACTIVE).findFirst().orElse(null);
        List<SigningKeyInfo> pending = all.stream().filter(k -> k.state() == KeyState.PENDING).toList();

        boolean hasValidActiveKey = active != null && now.isBefore(active.expiresAt());
        SigningKeyInfo ready = retireExpiredPendingAndFindReady(pending, now, hasValidActiveKey);
        if (ready != null) {
            retireSurplusPending(pending, ready, now);
            return promote(ready, all, now, auditEvents);
        }

        List<SigningKeyInfo> waiting = pending.stream().filter(k -> now.isBefore(k.expiresAt())).toList();
        if (active == null) {
            return waiting.isEmpty()
                    ? (all.isEmpty() ? createKey(KeyState.ACTIVE, now, now.plus(config.keyTtl()), auditEvents) : createPendingKey(now, auditEvents))
                    : waiting.get(0);
        }
        if (now.isBefore(active.expiresAt())) {
            return advanceWhileActiveIsValid(active, waiting, forced, now, auditEvents);
        }
        return waiting.isEmpty() ? createPendingKey(now, auditEvents) : waiting.get(0);
    }

    /**
     * Retires every pending key that expired before it could activate and returns the first remaining
     * one whose activation instant has passed, or {@code null} when none is ready.
     */
    private SigningKeyInfo retireExpiredPendingAndFindReady(List<SigningKeyInfo> pending, Instant now, boolean hasValidActiveKey) {
        SigningKeyInfo ready = null;
        for (SigningKeyInfo candidate : pending) {
            if (!now.isBefore(candidate.expiresAt())) {
                repository.updateState(candidate.kid(), KeyState.RETIRED, now);
            } else if (ready == null && !now.isBefore(activationInstant(candidate, hasValidActiveKey))) {
                ready = candidate;
            }
        }
        return ready;
    }

    /** Retires the unexpired pending keys other than the one being promoted. */
    private void retireSurplusPending(List<SigningKeyInfo> pending, SigningKeyInfo ready, Instant now) {
        for (SigningKeyInfo other : pending) {
            if (!other.kid().equals(ready.kid()) && now.isBefore(other.expiresAt())) {
                repository.updateState(other.kid(), KeyState.RETIRED, now);
            }
        }
    }

    /**
     * The active key is still valid: it keeps signing, and its successor is generated once
     * {@code publicationLead} remains before it expires, or at once when the rotation is forced.
     */
    private SigningKeyInfo advanceWhileActiveIsValid(SigningKeyInfo active, List<SigningKeyInfo> waiting,
                                                     boolean forced, Instant now,
                                                     List<Runnable> auditEvents) {
        if (!waiting.isEmpty()) {
            return forced ? waiting.get(0) : active;
        }
        if (forced) {
            return createPendingKey(now, auditEvents);
        }
        if (!now.isBefore(active.expiresAt().minus(config.publicationLead()))) {
            createKey(KeyState.PENDING, now,
                    max(active.expiresAt(), now.plus(config.jwksMaxAge())).plus(config.keyTtl()), auditEvents);
        }
        return active;
    }

    private SigningKeyInfo createPendingKey(Instant now, List<Runnable> auditEvents) {
        return createKey(KeyState.PENDING, now, now.plus(config.jwksMaxAge()).plus(config.keyTtl()), auditEvents);
    }

    private SigningKeyInfo promote(SigningKeyInfo ready, List<SigningKeyInfo> all, Instant now,
                                   List<Runnable> auditEvents) {
        repository.updateState(ready.kid(), KeyState.ACTIVE, null);
        Instant retiredAt = now.plus(config.publicationOverlap());
        String replaced = null;
        for (SigningKeyInfo old : all) {
            if (old.state() == KeyState.ACTIVE && !old.kid().equals(ready.kid())) {
                repository.updateState(old.kid(), KeyState.RETIRING, retiredAt);
                replaced = old.kid();
                if (auditBridge != null) {
                    String retiringKid = old.kid();
                    auditEvents.add(() -> auditBridge.logKeyRotated(ready.kid(), retiringKid));
                }
            }
        }
        if (replaced == null && auditBridge != null) {
            auditEvents.add(() -> auditBridge.logKeyRotated(ready.kid(), null));
        }
        return new SigningKeyInfo(ready.kid(), ready.algorithm(), KeyState.ACTIVE, ready.createdAt(),
                ready.expiresAt(), null);
    }

    private SigningKeyInfo createKey(KeyState state, Instant createdAt, Instant expiresAt,
                                     List<Runnable> auditEvents) {
        KeyPair keyPair = Ed25519Signer.generateKeyPair();
        byte[] rawPub = Ed25519Signer.extractRawPublicKeyBytes(keyPair.getPublic());
        byte[] privPkcs8 = keyPair.getPrivate().getEncoded();

        String kid = "k-" + UUID.randomUUID().toString().replace("-", "").substring(0, 16);
        Map<String, String> jwkParams = Rfc8037JwksBuilder.buildJwkParams(kid, rawPub);
        String jwkJson = Rfc8037JwksBuilder.serializeJwk(jwkParams);

        SigningKeyRecord keyRecord = new SigningKeyRecord(kid, Ed25519Signer.JWT_ALGORITHM, jwkJson, rawPub,
                privPkcs8, state, createdAt, expiresAt, null);
        repository.save(keyRecord);
        if (auditBridge != null) {
            auditEvents.add(() -> auditBridge.logKeyGenerated(kid));
        }
        return keyRecord.toInfo();
    }

    private static Instant max(Instant a, Instant b) {
        return a.isAfter(b) ? a : b;
    }

    @Override
    public int retireExpiredKeys() {
        Instant now = clock.instant();
        int retiredCount = 0;
        for (SigningKeyInfo key : repository.findAllInfo()) {
            if (key.state() == KeyState.RETIRING && key.retiredAt() != null && !now.isBefore(key.retiredAt())) {
                repository.updateState(key.kid(), KeyState.RETIRED, key.retiredAt());
                if (auditBridge != null) {
                    auditBridge.logKeyRetired(key.kid());
                }
                retiredCount++;
            }
        }
        return retiredCount;
    }

    @Override
    public List<SigningKeyInfo> listKeyGenerations() {
        return repository.findAllInfo();
    }

    @Override
    public SigningKeyInfo activeKey() {
        return repository.findAllInfo().stream()
                .filter(k -> k.state() == KeyState.ACTIVE)
                .findFirst()
                .orElseThrow(() -> new NoActiveKeyException("No active signing key available"));
    }
}
