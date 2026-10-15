package eu.exeris.caps.tokenissuer.internal.repository;

import eu.exeris.caps.tokenissuer.api.KeyState;
import eu.exeris.caps.tokenissuer.api.SigningKeyInfo;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Thread-safe in-memory implementation of {@link SigningKeyRepository}.
 *
 * <p>Used for standalone runtime, unit testing, and ephemeral environments.
 *
 * @since 0.1.0
 */
public final class InMemorySigningKeyRepository implements SigningKeyRepository {

    private final Map<String, SigningKeyRecord> keys = new ConcurrentHashMap<>();

    @Override
    public synchronized void save(SigningKeyRecord record) {
        Objects.requireNonNull(record, "record must not be null");
        keys.put(record.kid(), record);
    }

    @Override
    public synchronized Optional<SigningKeyRecord> findActive() {
        return keys.values().stream()
                .filter(k -> k.state() == KeyState.ACTIVE)
                .max(Comparator.comparing(SigningKeyRecord::createdAt));
    }

    @Override
    public synchronized Optional<SigningKeyRecord> findByKid(String kid) {
        Objects.requireNonNull(kid, "kid must not be null");
        return Optional.ofNullable(keys.get(kid));
    }

    @Override
    public synchronized List<PublicSigningKey> findPublishablePublicKeys(Instant now) {
        Objects.requireNonNull(now, "now must not be null");
        return keys.values().stream()
                .filter(k -> k.state() == KeyState.ACTIVE
                        || k.state() == KeyState.PENDING
                        || (k.state() == KeyState.RETIRING && k.retiredAt() != null && now.isBefore(k.retiredAt())))
                .sorted(Comparator.comparing(SigningKeyRecord::createdAt).reversed())
                .map(k -> new PublicSigningKey(k.kid(), k.publicKeyRawBytes()))
                .toList();
    }

    @Override
    public synchronized List<SigningKeyInfo> findAllInfo() {
        return keys.values().stream()
                .sorted(Comparator.comparing(SigningKeyRecord::createdAt).reversed())
                .map(SigningKeyRecord::toInfo)
                .toList();
    }

    @Override
    public synchronized void updateState(String kid, KeyState state, Instant retiredAt) {
        Objects.requireNonNull(kid, "kid must not be null");
        Objects.requireNonNull(state, "state must not be null");
        SigningKeyRecord existing = keys.get(kid);
        if (existing != null) {
            SigningKeyRecord updated = new SigningKeyRecord(
                    existing.kid(),
                    existing.algorithm(),
                    existing.publicKeyJwkJson(),
                    existing.publicKeyRawBytes(),
                    existing.privateKeyPkcs8Bytes(),
                    state,
                    existing.createdAt(),
                    existing.expiresAt(),
                    retiredAt != null ? retiredAt : existing.retiredAt()
            );
            keys.put(kid, updated);
        }
    }

    @Override
    public synchronized int deleteRetiredBefore(Instant cutoff) {
        Objects.requireNonNull(cutoff, "cutoff must not be null");
        List<String> toRemove = new ArrayList<>();
        for (SigningKeyRecord record : keys.values()) {
            if (record.state() == KeyState.RETIRED) {
                Instant ref = record.retiredAt() != null ? record.retiredAt() : record.expiresAt();
                if (ref.isBefore(cutoff)) {
                    toRemove.add(record.kid());
                }
            }
        }
        toRemove.forEach(keys::remove);
        return toRemove.size();
    }

    public synchronized void clear() {
        keys.clear();
    }
}
