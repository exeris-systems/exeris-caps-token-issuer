package eu.exeris.caps.tokenissuer.internal.repository;

import eu.exeris.caps.tokenissuer.api.KeyState;
import eu.exeris.caps.tokenissuer.api.SigningKeyInfo;
import eu.exeris.caps.tokenissuer.internal.custody.KeyEncryptionKeyring;
import eu.exeris.caps.tokenissuer.internal.custody.SigningKeyEnvelope;
import eu.exeris.kernel.spi.persistence.PersistenceStatement;
import eu.exeris.kernel.spi.persistence.QueryResult;
import eu.exeris.kernel.spi.persistence.RowCursor;
import eu.exeris.kernel.spi.persistence.TransactionalExecutor;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

/**
 * PostgreSQL implementation of {@link SigningKeyRepository} over the kernel {@link TransactionalExecutor}.
 *
 * <p>Private keys are stored only as {@link SigningKeyEnvelope} envelopes sealed under the
 * configured {@link KeyEncryptionKeyring}; the repository cannot be built without one, and a row
 * whose private key does not open under it is refused on read rather than returned as is.
 *
 * @since 0.1.0
 */
public final class PostgresSigningKeyRepository implements SigningKeyRepository {

    public static final long EXERIS_ROTATION_LOCK_ID = 5001272635418181633L;

    private final TransactionalExecutor tx;
    private final SigningKeyEnvelope envelope;

    public PostgresSigningKeyRepository(TransactionalExecutor tx, KeyEncryptionKeyring keyring) {
        this.tx = Objects.requireNonNull(tx, "TransactionalExecutor must not be null");
        this.envelope = new SigningKeyEnvelope(Objects.requireNonNull(keyring, "keyring must not be null"));
    }

    /**
     * Re-seals every stored private key whose envelope names a KEK other than the active one, so the
     * older KEK can be removed from the keyring afterwards.
     *
     * @return number of records re-sealed
     */
    public int resealWithActiveKek() {
        AtomicInteger count = new AtomicInteger();
        rotateUnderClusterLock(() -> {
            String activeKekId = envelope.activeKekId();
            List<String> stale = tx.query(conn -> {
                try (PersistenceStatement stmt = conn.prepare("SELECT kid, private_key_pkcs8 FROM exeris_signing_keys")) {
                    try (QueryResult rs = stmt.executeQuery()) {
                        List<String> kids = new ArrayList<>();
                        while (rs.next()) {
                            RowCursor row = rs.row();
                            if (!activeKekId.equals(SigningKeyEnvelope.kekIdOf(row.getBytes(1)))) {
                                kids.add(row.getString(0));
                            }
                        }
                        return kids;
                    }
                }
            });
            for (String kid : stale) {
                findByKid(kid).ifPresent(record -> {
                    save(record);
                    count.incrementAndGet();
                });
            }
            return null;
        });
        return count.get();
    }

    @Override
    public SigningKeyInfo rotateUnderClusterLock(Supplier<SigningKeyInfo> rotationLogic) {
        Objects.requireNonNull(rotationLogic, "rotationLogic must not be null");
        AtomicReference<SigningKeyInfo> ref = new AtomicReference<>();
        tx.executeManaged(conn -> {
            try (PersistenceStatement stmt = conn.prepare("SELECT pg_advisory_xact_lock($1)")) {
                stmt.bindLong(0, EXERIS_ROTATION_LOCK_ID);
                try (QueryResult rs = stmt.executeQuery()) {
                    // Lock held for duration of transaction
                }
            }
            ref.set(rotationLogic.get());
        });
        return ref.get();
    }

    @Override
    public void save(SigningKeyRecord record) {
        Objects.requireNonNull(record, "record must not be null");
        String sql = """
                INSERT INTO exeris_signing_keys (kid, algorithm, public_key_jwk, public_key_bytes, private_key_pkcs8, state, created_at, expires_at, retired_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                ON CONFLICT (kid) DO UPDATE SET
                    algorithm = EXCLUDED.algorithm,
                    public_key_jwk = EXCLUDED.public_key_jwk,
                    public_key_bytes = EXCLUDED.public_key_bytes,
                    private_key_pkcs8 = EXCLUDED.private_key_pkcs8,
                    state = EXCLUDED.state,
                    expires_at = EXCLUDED.expires_at,
                    retired_at = EXCLUDED.retired_at
                """;
        tx.executeManaged(conn -> {
            try (PersistenceStatement stmt = conn.prepare(sql)) {
                stmt.bindString(0, record.kid())
                    .bindString(1, record.algorithm())
                    .bindString(2, record.publicKeyJwkJson())
                    .bindBytes(3, record.publicKeyRawBytes())
                    .bindBytes(4, envelope.seal(record.kid(), record.privateKeyPkcs8Bytes()))
                    .bindString(5, record.state().name())
                    .bindInstant(6, record.createdAt())
                    .bindInstant(7, record.expiresAt());

                if (record.retiredAt() != null) {
                    stmt.bindInstant(8, record.retiredAt());
                } else {
                    stmt.bindNull(8);
                }

                stmt.executeUpdate();
            }
        });
    }

    @Override
    public Optional<SigningKeyRecord> findActive() {
        String sql = """
                SELECT kid, algorithm, public_key_jwk, public_key_bytes, private_key_pkcs8, state, created_at, expires_at, retired_at
                FROM exeris_signing_keys
                WHERE state = $1
                ORDER BY created_at DESC
                LIMIT 1
                """;
        return tx.query(conn -> {
            try (PersistenceStatement stmt = conn.prepare(sql)) {
                stmt.bindString(0, KeyState.ACTIVE.name());
                try (QueryResult rs = stmt.executeQuery()) {
                    if (rs.next()) {
                        return Optional.of(mapRow(rs.row()));
                    }
                    return Optional.empty();
                }
            }
        });
    }

    @Override
    public Optional<SigningKeyRecord> findByKid(String kid) {
        Objects.requireNonNull(kid, "kid must not be null");
        String sql = """
                SELECT kid, algorithm, public_key_jwk, public_key_bytes, private_key_pkcs8, state, created_at, expires_at, retired_at
                FROM exeris_signing_keys
                WHERE kid = $1
                """;
        return tx.query(conn -> {
            try (PersistenceStatement stmt = conn.prepare(sql)) {
                stmt.bindString(0, kid);
                try (QueryResult rs = stmt.executeQuery()) {
                    if (rs.next()) {
                        return Optional.of(mapRow(rs.row()));
                    }
                    return Optional.empty();
                }
            }
        });
    }

    @Override
    public List<SigningKeyRecord> findPublishable(Instant now, Duration overlapWindow) {
        Objects.requireNonNull(now, "now must not be null");
        Objects.requireNonNull(overlapWindow, "overlapWindow must not be null");
        String sql = """
                SELECT kid, algorithm, public_key_jwk, public_key_bytes, private_key_pkcs8, state, created_at, expires_at, retired_at
                FROM exeris_signing_keys
                WHERE state = 'ACTIVE' OR state = 'RETIRING'
                ORDER BY created_at DESC
                """;
        return tx.query(conn -> {
            try (PersistenceStatement stmt = conn.prepare(sql)) {
                try (QueryResult rs = stmt.executeQuery()) {
                    List<SigningKeyRecord> list = new ArrayList<>();
                    while (rs.next()) {
                        SigningKeyRecord rec = mapRow(rs.row());
                        if (rec.state() == KeyState.ACTIVE) {
                            list.add(rec);
                        } else if (rec.state() == KeyState.RETIRING) {
                            Instant effectiveRetire = rec.retiredAt() != null
                                    ? rec.retiredAt()
                                    : rec.expiresAt().plus(overlapWindow);
                            if (now.isBefore(effectiveRetire)) {
                                list.add(rec);
                            }
                        }
                    }
                    return list;
                }
            }
        });
    }

    @Override
    public List<SigningKeyRecord> findAll() {
        String sql = """
                SELECT kid, algorithm, public_key_jwk, public_key_bytes, private_key_pkcs8, state, created_at, expires_at, retired_at
                FROM exeris_signing_keys
                ORDER BY created_at DESC
                """;
        return tx.query(conn -> {
            try (PersistenceStatement stmt = conn.prepare(sql)) {
                try (QueryResult rs = stmt.executeQuery()) {
                    List<SigningKeyRecord> list = new ArrayList<>();
                    while (rs.next()) {
                        list.add(mapRow(rs.row()));
                    }
                    return list;
                }
            }
        });
    }

    @Override
    public void updateState(String kid, KeyState state, Instant retiredAt) {
        Objects.requireNonNull(kid, "kid must not be null");
        Objects.requireNonNull(state, "state must not be null");
        String sql = """
                UPDATE exeris_signing_keys
                SET state = $1, retired_at = $2
                WHERE kid = $3
                """;
        tx.executeManaged(conn -> {
            try (PersistenceStatement stmt = conn.prepare(sql)) {
                stmt.bindString(0, state.name());
                if (retiredAt != null) {
                    stmt.bindInstant(1, retiredAt);
                } else {
                    stmt.bindNull(1);
                }
                stmt.bindString(2, kid);
                stmt.executeUpdate();
            }
        });
    }

    @Override
    public int deleteRetiredBefore(Instant cutoff) {
        Objects.requireNonNull(cutoff, "cutoff must not be null");
        String sql = """
                DELETE FROM exeris_signing_keys
                WHERE state = $1 AND (retired_at < $2 OR (retired_at IS NULL AND expires_at < $2))
                """;
        AtomicInteger count = new AtomicInteger(0);
        tx.executeManaged(conn -> {
            try (PersistenceStatement stmt = conn.prepare(sql)) {
                stmt.bindString(0, KeyState.RETIRED.name());
                stmt.bindInstant(1, cutoff);
                count.set((int) stmt.executeUpdate());
            }
        });
        return count.get();
    }

    private SigningKeyRecord mapRow(RowCursor row) {
        String kid = row.getString(0);
        String alg = row.getString(1);
        String jwkJson = row.getString(2);
        byte[] pubBytes = row.getBytes(3);
        byte[] privBytes = envelope.open(kid, row.getBytes(4));
        KeyState state = KeyState.valueOf(row.getString(5));
        Instant createdAt = row.getInstant(6);
        Instant expiresAt = row.getInstant(7);
        Instant retiredAt = row.isNull(8) ? null : row.getInstant(8);

        return new SigningKeyRecord(kid, alg, jwkJson, pubBytes, privBytes, state, createdAt, expiresAt, retiredAt);
    }
}
