package eu.exeris.caps.tokenissuer.internal.repository;

import eu.exeris.caps.tokenissuer.api.KeyState;
import eu.exeris.caps.tokenissuer.api.SigningKeyInfo;
import eu.exeris.kernel.spi.persistence.PersistenceStatement;
import eu.exeris.kernel.spi.persistence.QueryResult;
import eu.exeris.kernel.spi.persistence.RowCursor;
import eu.exeris.kernel.spi.persistence.TransactionalExecutor;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

/**
 * PostgreSQL implementation of {@link SigningKeyRepository} using {@link TransactionalExecutor}.
 *
 * @since 0.1.0
 */
public final class PostgresSigningKeyRepository implements SigningKeyRepository {

    public static final long EXERIS_ROTATION_LOCK_ID = 5001272635418181633L;
    private static final byte[] ENVELOPE_MAGIC = new byte[]{0x45, 0x4E, 0x56, 0x01}; // "ENV\1"
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH_BITS = 128;

    private final TransactionalExecutor tx;
    private final SecretKey masterKey;
    private final SecureRandom secureRandom = new SecureRandom();

    public PostgresSigningKeyRepository(TransactionalExecutor tx) {
        this(tx, resolveDefaultMasterKey());
    }

    public PostgresSigningKeyRepository(TransactionalExecutor tx, byte[] masterKeyBytes) {
        this(tx, new SecretKeySpec(Objects.requireNonNull(masterKeyBytes, "masterKeyBytes must not be null"), "AES"));
    }

    public PostgresSigningKeyRepository(TransactionalExecutor tx, SecretKey masterKey) {
        this.tx = Objects.requireNonNull(tx, "TransactionalExecutor must not be null");
        this.masterKey = Objects.requireNonNull(masterKey, "masterKey must not be null");
    }

    private static SecretKey resolveDefaultMasterKey() {
        String env = System.getenv("EXERIS_MASTER_KEY");
        if (env != null && !env.isBlank()) {
            return parseKey(env);
        }
        String prop = System.getProperty("exeris.master.key");
        if (prop != null && !prop.isBlank()) {
            return parseKey(prop);
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] keyBytes = digest.digest("exeris-default-signing-key-envelope-secret".getBytes(StandardCharsets.UTF_8));
            return new SecretKeySpec(keyBytes, "AES");
        } catch (Exception e) {
            throw new IllegalStateException("Failed to initialize default master key", e);
        }
    }

    private static SecretKey parseKey(String keyStr) {
        try {
            byte[] decoded = Base64.getDecoder().decode(keyStr.trim());
            if (decoded.length == 32) {
                return new SecretKeySpec(decoded, "AES");
            }
        } catch (Exception ignored) {
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] keyBytes = digest.digest(keyStr.getBytes(StandardCharsets.UTF_8));
            return new SecretKeySpec(keyBytes, "AES");
        } catch (Exception e) {
            throw new IllegalStateException("Failed to parse master key", e);
        }
    }

    private byte[] encryptPrivateKey(byte[] plain) {
        if (plain == null || plain.length == 0) {
            return plain;
        }
        try {
            byte[] iv = new byte[GCM_IV_LENGTH];
            secureRandom.nextBytes(iv);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, masterKey, new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));
            byte[] ciphertext = cipher.doFinal(plain);

            byte[] result = new byte[ENVELOPE_MAGIC.length + GCM_IV_LENGTH + ciphertext.length];
            System.arraycopy(ENVELOPE_MAGIC, 0, result, 0, ENVELOPE_MAGIC.length);
            System.arraycopy(iv, 0, result, ENVELOPE_MAGIC.length, GCM_IV_LENGTH);
            System.arraycopy(ciphertext, 0, result, ENVELOPE_MAGIC.length + GCM_IV_LENGTH, ciphertext.length);
            return result;
        } catch (Exception e) {
            throw new IllegalStateException("Envelope encryption of private key failed", e);
        }
    }

    private byte[] decryptPrivateKey(byte[] stored) {
        if (stored == null || stored.length < ENVELOPE_MAGIC.length + GCM_IV_LENGTH) {
            return stored;
        }
        boolean hasMagic = true;
        for (int i = 0; i < ENVELOPE_MAGIC.length; i++) {
            if (stored[i] != ENVELOPE_MAGIC[i]) {
                hasMagic = false;
                break;
            }
        }
        if (!hasMagic) {
            return stored;
        }
        try {
            byte[] iv = Arrays.copyOfRange(stored, ENVELOPE_MAGIC.length, ENVELOPE_MAGIC.length + GCM_IV_LENGTH);
            byte[] ciphertext = Arrays.copyOfRange(stored, ENVELOPE_MAGIC.length + GCM_IV_LENGTH, stored.length);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, masterKey, new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));
            return cipher.doFinal(ciphertext);
        } catch (Exception e) {
            throw new IllegalStateException("Envelope decryption of private key failed", e);
        }
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
                    .bindBytes(4, encryptPrivateKey(record.privateKeyPkcs8Bytes()))
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
        java.util.concurrent.atomic.AtomicInteger count = new java.util.concurrent.atomic.AtomicInteger(0);
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
        byte[] privBytes = decryptPrivateKey(row.getBytes(4));
        KeyState state = KeyState.valueOf(row.getString(5));
        Instant createdAt = row.getInstant(6);
        Instant expiresAt = row.getInstant(7);
        Instant retiredAt = row.isNull(8) ? null : row.getInstant(8);

        return new SigningKeyRecord(kid, alg, jwkJson, pubBytes, privBytes, state, createdAt, expiresAt, retiredAt);
    }
}
