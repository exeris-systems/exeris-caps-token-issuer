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
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * Default implementation of {@link SigningKeyRotation}.
 *
 * <p>A key signs for {@link TokenIssuerConfig#keyTtl()}. When it is replaced it becomes
 * {@link KeyState#RETIRING} with {@code retiredAt = now + maxTokenTtl + clockSkew}: the last token
 * it signed cannot be accepted by any verifier after that instant, so the key stays in the JWKS
 * exactly until then. Every instant comes from the injected {@link Clock}.
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

    public synchronized void startScheduledRotation() {
        if (jobScheduler != null && rotationJobHandle == null) {
            JobDescriptor descriptor = new JobDescriptor(
                    ROTATION_JOB_NAME,
                    new JobTrigger.FixedInterval(config.rotationCheckInterval(), config.rotationCheckInterval()),
                    this::runScheduledCycle
            );
            this.rotationJobHandle = jobScheduler.submit(descriptor);
        }
    }

    public synchronized void stopScheduledRotation() {
        if (rotationJobHandle != null) {
            rotationJobHandle.cancel();
            rotationJobHandle = null;
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
     * One maintenance cycle: rotate if due, retire keys past their publication window, and delete
     * the private key material of retired keys.
     */
    void runMaintenanceCycle() {
        rotateIfDue();
        retireExpiredKeys();
        repository.deleteRetiredBefore(clock.instant());
    }

    public synchronized SigningKeyInfo ensureActiveKey() {
        return rotateIfDue();
    }

    @Override
    public SigningKeyInfo rotateIfDue() {
        Optional<SigningKeyRecord> active = repository.findActive();
        if (active.isPresent() && clock.instant().isBefore(active.get().expiresAt())) {
            return active.get().toInfo();
        }
        return rotate(active.map(SigningKeyRecord::kid).orElse(null), true);
    }

    @Override
    public SigningKeyInfo rotateKeys() {
        return rotate(repository.findActive().map(SigningKeyRecord::kid).orElse(null), false);
    }

    /**
     * Rotates under the repository's cluster lock. {@code observedActiveKid} is the active key the
     * caller saw before taking the lock; if another node rotated in between, its key is kept.
     */
    private SigningKeyInfo rotate(String observedActiveKid, boolean onlyIfDue) {
        return repository.rotateUnderClusterLock(() -> {
            synchronized (this) {
                try {
                    Instant now = clock.instant();
                    Optional<SigningKeyRecord> currentActive = repository.findActive();
                    if (currentActive.isPresent()) {
                        SigningKeyRecord current = currentActive.get();
                        boolean rotatedElsewhere = !current.kid().equals(observedActiveKid);
                        boolean stillValid = now.isBefore(current.expiresAt());
                        if (onlyIfDue ? stillValid : rotatedElsewhere) {
                            return current.toInfo();
                        }
                    }

                    KeyPair keyPair = Ed25519Signer.generateKeyPair();
                    byte[] rawPub = Ed25519Signer.extractRawPublicKeyBytes(keyPair.getPublic());
                    byte[] privPkcs8 = keyPair.getPrivate().getEncoded();

                    String kid = "k-" + UUID.randomUUID().toString().replace("-", "").substring(0, 16);
                    Map<String, String> jwkParams = Rfc8037JwksBuilder.buildJwkParams(kid, rawPub);
                    String jwkJson = Rfc8037JwksBuilder.serializeJwk(jwkParams);

                    SigningKeyRecord newActive = new SigningKeyRecord(
                            kid,
                            Ed25519Signer.JWT_ALGORITHM,
                            jwkJson,
                            rawPub,
                            privPkcs8,
                            KeyState.ACTIVE,
                            now,
                            now.plus(config.keyTtl()),
                            null
                    );
                    // The new key is stored before the old one stops signing, so an issuer never
                    // observes a moment without an active key.
                    repository.save(newActive);

                    // Every other ACTIVE key retires, not only the one observed: a rotation interrupted
                    // between the save and this step would otherwise leave a key active forever.
                    Instant retiredAt = now.plus(config.publicationOverlap());
                    boolean replacedAny = false;
                    for (SigningKeyRecord rec : repository.findAll()) {
                        if (rec.state() == KeyState.ACTIVE && !rec.kid().equals(kid)) {
                            repository.updateState(rec.kid(), KeyState.RETIRING, retiredAt);
                            replacedAny = true;
                            if (auditBridge != null) {
                                auditBridge.logKeyRotated(kid, rec.kid());
                            }
                        }
                    }
                    if (!replacedAny && auditBridge != null) {
                        auditBridge.logKeyGenerated(kid);
                    }
                    return newActive.toInfo();
                } catch (TokenIssuerException e) {
                    throw e;
                } catch (RuntimeException e) {
                    throw new KeyRotationException("Failed to rotate signing keys", e);
                }
            }
        });
    }

    @Override
    public synchronized int retireExpiredKeys() {
        Instant now = clock.instant();
        int retiredCount = 0;
        for (SigningKeyRecord rec : repository.findAll()) {
            if (rec.state() == KeyState.RETIRING && rec.retiredAt() != null && !now.isBefore(rec.retiredAt())) {
                repository.updateState(rec.kid(), KeyState.RETIRED, rec.retiredAt());
                if (auditBridge != null) {
                    auditBridge.logKeyRetired(rec.kid());
                }
                retiredCount++;
            }
        }
        return retiredCount;
    }

    @Override
    public List<SigningKeyInfo> listKeyGenerations() {
        return repository.findAll().stream()
                .map(SigningKeyRecord::toInfo)
                .toList();
    }

    @Override
    public SigningKeyInfo activeKey() {
        return repository.findActive()
                .map(SigningKeyRecord::toInfo)
                .orElseThrow(() -> new NoActiveKeyException("No active signing key available"));
    }
}
