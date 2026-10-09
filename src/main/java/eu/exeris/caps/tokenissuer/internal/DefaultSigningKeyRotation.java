package eu.exeris.caps.tokenissuer.internal;

import eu.exeris.caps.tokenissuer.api.KeyRotationPolicy;
import eu.exeris.caps.tokenissuer.api.KeyState;
import eu.exeris.caps.tokenissuer.api.SigningKeyInfo;
import eu.exeris.caps.tokenissuer.api.SigningKeyRotation;
import eu.exeris.caps.tokenissuer.api.exception.KeyRotationException;
import eu.exeris.caps.tokenissuer.api.exception.NoActiveKeyException;
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
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * Default implementation of {@link SigningKeyRotation}.
 *
 * @since 0.1.0
 */
public final class DefaultSigningKeyRotation implements SigningKeyRotation {

    private final SigningKeyRepository repository;
    private final KeyRotationPolicy policy;
    private final TokenIssuerAuditBridge auditBridge;
    private final JobScheduler jobScheduler;
    private JobHandle rotationJobHandle;

    public DefaultSigningKeyRotation(
            SigningKeyRepository repository,
            KeyRotationPolicy policy,
            TokenIssuerAuditBridge auditBridge,
            JobScheduler jobScheduler
    ) {
        this.repository = Objects.requireNonNull(repository, "repository must not be null");
        this.policy = Objects.requireNonNull(policy, "policy must not be null");
        this.auditBridge = auditBridge;
        this.jobScheduler = jobScheduler;
    }

    public DefaultSigningKeyRotation(
            SigningKeyRepository repository,
            KeyRotationPolicy policy,
            TokenIssuerAuditBridge auditBridge
    ) {
        this(repository, policy, auditBridge, null);
    }

    public synchronized void startScheduledRotation() {
        if (jobScheduler != null && rotationJobHandle == null) {
            JobDescriptor descriptor = new JobDescriptor(
                    "exeris-token-issuer-key-rotation",
                    new JobTrigger.FixedInterval(policy.rotationInterval(), policy.rotationInterval()),
                    () -> {
                        try {
                            rotateKeys();
                            retireExpiredKeys();
                        } catch (Exception ignored) {
                            // Suppress failure inside scheduled cycle to avoid crashing daemon
                        }
                    }
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

    public synchronized SigningKeyInfo ensureActiveKey() {
        Optional<SigningKeyRecord> existing = repository.findActive();
        if (existing.isPresent()) {
            return existing.get().toInfo();
        }
        return rotateKeys();
    }

    @Override
    public SigningKeyInfo rotateKeys() {
        Optional<SigningKeyRecord> priorActive = repository.findActive();
        String priorActiveKid = priorActive.map(SigningKeyRecord::kid).orElse(null);

        return repository.rotateUnderClusterLock(() -> {
            synchronized (this) {
                try {
                    Instant now = Instant.now();
                    Optional<SigningKeyRecord> currentActive = repository.findActive();

                    if (priorActiveKid != null && currentActive.isPresent() && !currentActive.get().kid().equals(priorActiveKid)) {
                        return currentActive.get().toInfo();
                    }

                    // 1. Generate new Ed25519 key pair
                    KeyPair keyPair = Ed25519Signer.generateKeyPair();
                    byte[] rawPub = Ed25519Signer.extractRawPublicKeyBytes(keyPair.getPublic());
                    byte[] privPkcs8 = keyPair.getPrivate().getEncoded();

                    String kid = "k-" + UUID.randomUUID().toString().replace("-", "").substring(0, 16);
                    Map<String, String> jwkParams = Rfc8037JwksBuilder.buildJwkParams(kid, rawPub);
                    String jwkJson = Rfc8037JwksBuilder.serializeJwk(jwkParams);

                    Instant expiresAt = now.plus(policy.keyTtl());

                    // 2. Mark previous key as RETIRING
                    if (currentActive.isPresent()) {
                        SigningKeyRecord old = currentActive.get();
                        Instant retiredAt = now.plus(policy.overlapWindow());
                        repository.updateState(old.kid(), KeyState.RETIRING, retiredAt);
                        if (auditBridge != null) {
                            auditBridge.logKeyRotated(kid, old.kid());
                        }
                    } else {
                        if (auditBridge != null) {
                            auditBridge.logKeyGenerated(kid);
                        }
                    }

                    // 3. Save new active key
                    SigningKeyRecord newActive = new SigningKeyRecord(
                            kid,
                            Ed25519Signer.JWT_ALGORITHM,
                            jwkJson,
                            rawPub,
                            privPkcs8,
                            KeyState.ACTIVE,
                            now,
                            expiresAt,
                            null
                    );
                    repository.save(newActive);

                    return newActive.toInfo();
                } catch (Exception e) {
                    throw new KeyRotationException("Failed to rotate signing keys", e);
                }
            }
        });
    }

    @Override
    public synchronized int retireExpiredKeys() {
        Instant now = Instant.now();
        List<SigningKeyRecord> records = repository.findAll();
        int retiredCount = 0;
        for (SigningKeyRecord rec : records) {
            if (rec.state() == KeyState.RETIRING) {
                Instant effectiveRetireAt = rec.retiredAt() != null
                        ? rec.retiredAt()
                        : rec.expiresAt().plus(policy.overlapWindow());
                if (now.isAfter(effectiveRetireAt)) {
                    repository.updateState(rec.kid(), KeyState.RETIRED, now);
                    if (auditBridge != null) {
                        auditBridge.logKeyRetired(rec.kid());
                    }
                    retiredCount++;
                }
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
