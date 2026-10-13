package eu.exeris.caps.tokenissuer.internal.repository;

import eu.exeris.caps.tokenissuer.api.KeyState;
import eu.exeris.caps.tokenissuer.api.exception.SigningKeyCustodyException;
import eu.exeris.caps.tokenissuer.internal.custody.KeyEncryptionKeyring;
import eu.exeris.caps.tokenissuer.internal.custody.SigningKeyEnvelope;
import eu.exeris.caps.tokenissuer.testing.TestSupport;
import eu.exeris.kernel.spi.persistence.PersistenceConnection;
import eu.exeris.kernel.spi.persistence.PersistenceStatement;
import eu.exeris.kernel.spi.persistence.QueryResult;
import eu.exeris.kernel.spi.persistence.RowCursor;
import eu.exeris.kernel.spi.persistence.TransactionIsolation;
import eu.exeris.kernel.spi.persistence.TransactionalExecutor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("PostgresSigningKeyRepository Unit Tests")
class PostgresSigningKeyRepositoryTest {

    private CapturingTransactionalExecutor tx;
    private PostgresSigningKeyRepository repository;

    @BeforeEach
    void setUp() {
        tx = new CapturingTransactionalExecutor();
        repository = new PostgresSigningKeyRepository(tx,
                KeyEncryptionKeyring.parse("TEST", "k1:" + TestSupport.newKek()));
    }

    @Test
    @DisplayName("save executes managed insert into exeris_signing_keys")
    void saveExecutesManagedInsert() {
        Instant now = Instant.now();
        Instant exp = now.plus(Duration.ofDays(7));
        SigningKeyRecord record = new SigningKeyRecord(
                "k-test-1",
                "EdDSA",
                "{\"kty\":\"OKP\"}",
                new byte[32],
                new byte[32],
                KeyState.ACTIVE,
                now,
                exp,
                null
        );

        repository.save(record);

        assertThat(tx.executedStatements).hasSize(1);
        CapturingStatement stmt = tx.executedStatements.get(0);
        assertThat(stmt.sql).contains("INSERT INTO exeris_signing_keys");
        assertThat(stmt.boundParameters.get(0)).isEqualTo("k-test-1");
        assertThat(stmt.boundParameters.get(1)).isEqualTo("EdDSA");
        assertThat(stmt.boundParameters.get(5)).isEqualTo("ACTIVE");
    }

    @Test
    @DisplayName("updateState executes UPDATE query on key state and retired timestamp")
    void updateStateExecutesUpdate() {
        Instant retiredAt = Instant.now();
        repository.updateState("k-test-1", KeyState.RETIRED, retiredAt);

        assertThat(tx.executedStatements).hasSize(1);
        CapturingStatement stmt = tx.executedStatements.get(0);
        assertThat(stmt.sql).contains("UPDATE exeris_signing_keys");
        assertThat(stmt.boundParameters.get(0)).isEqualTo("RETIRED");
        assertThat(stmt.boundParameters.get(1)).isEqualTo(retiredAt);
        assertThat(stmt.boundParameters.get(2)).isEqualTo("k-test-1");
    }

    @Test
    @DisplayName("deleteRetiredBefore executes DELETE on expired retired keys")
    void deleteRetiredBeforeExecutesDelete() {
        Instant cutoff = Instant.now().minus(Duration.ofDays(1));
        tx.rowsAffectedResult = 3;

        int deleted = repository.deleteRetiredBefore(cutoff);

        assertThat(deleted).isEqualTo(3);
        assertThat(tx.executedStatements).hasSize(1);
        CapturingStatement stmt = tx.executedStatements.get(0);
        assertThat(stmt.sql).contains("DELETE FROM exeris_signing_keys");
        assertThat(stmt.boundParameters.get(0)).isEqualTo("RETIRED");
        assertThat(stmt.boundParameters.get(1)).isEqualTo(cutoff);
    }

    @Test
    @DisplayName("save stores the private key only as a sealed envelope naming the active KEK")
    void saveSealsPrivateKey() {
        byte[] rawPriv = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};
        SigningKeyRecord record = new SigningKeyRecord(
                "k-enc-1",
                "EdDSA",
                "{}",
                new byte[32],
                rawPriv,
                KeyState.ACTIVE,
                Instant.now(),
                Instant.now().plus(Duration.ofDays(1)),
                null
        );

        repository.save(record);

        CapturingStatement stmt = tx.executedStatements.get(0);
        byte[] stored = (byte[]) stmt.boundParameters.get(4);
        assertThat(stored).startsWith(new byte[]{'E', 'X', 'K', 0x01});
        assertThat(SigningKeyEnvelope.kekIdOf(stored)).isEqualTo("k1");
        assertThat(java.util.Collections.indexOfSubList(toList(stored), toList(rawPriv))).isEqualTo(-1);
    }

    @Test
    @DisplayName("a row whose private key is plaintext is refused on read, never passed through")
    void plaintextRowRefused() {
        Instant now = Instant.now();
        tx.queryResultSupplier = () -> new StubQueryResult(List.<Object[]>of(new Object[]{
                "k-plain", "EdDSA", "{}", new byte[32], new byte[]{0x30, 0x2e, 0x02, 0x01},
                "ACTIVE", now, now.plus(Duration.ofDays(1)), null}));

        assertThatThrownBy(() -> repository.findByKid("k-plain"))
                .isInstanceOf(SigningKeyCustodyException.class)
                .satisfies(e -> assertThat(((SigningKeyCustodyException) e).reason())
                        .isEqualTo(SigningKeyCustodyException.Reason.NOT_SEALED));
    }

    private static List<Byte> toList(byte[] bytes) {
        List<Byte> list = new ArrayList<>(bytes.length);
        for (byte b : bytes) {
            list.add(b);
        }
        return list;
    }

    @Test
    @DisplayName("rotateUnderClusterLock acquires pg_advisory_xact_lock")
    void rotateUnderClusterLockAcquiresAdvisoryLock() {
        var result = repository.rotateUnderClusterLock(() -> null);

        assertThat(tx.executedStatements).hasSize(1);
        CapturingStatement stmt = tx.executedStatements.get(0);
        assertThat(stmt.sql).contains("pg_advisory_xact_lock");
        assertThat(stmt.boundParameters.get(0)).isEqualTo(PostgresSigningKeyRepository.EXERIS_ROTATION_LOCK_ID);
    }

    private static final class CapturingTransactionalExecutor implements TransactionalExecutor {
        final List<CapturingStatement> executedStatements = new ArrayList<>();
        Supplier<QueryResult> queryResultSupplier;
        long rowsAffectedResult = 1;

        @Override
        public void execute(TransactionalWork work) {
            work.run(new CapturingConnection(this));
        }

        @Override
        public void executeManaged(TransactionalWork work) {
            work.run(new CapturingConnection(this));
        }

        @Override
        public void executeManaged(TransactionIsolation isolation, boolean readOnly, TransactionalWork work) {
            work.run(new CapturingConnection(this));
        }

        @Override
        public <T> T query(Function<PersistenceConnection, T> query) {
            return query.apply(new CapturingConnection(this));
        }
    }

    private static final class CapturingConnection implements PersistenceConnection {
        private final CapturingTransactionalExecutor executor;

        CapturingConnection(CapturingTransactionalExecutor executor) {
            this.executor = executor;
        }

        @Override
        public PersistenceStatement prepare(String sql) {
            CapturingStatement stmt = new CapturingStatement(sql, executor);
            executor.executedStatements.add(stmt);
            return stmt;
        }

        @Override public QueryResult executeQuery(String sql) { return null; }
        @Override public long executeUpdate(String sql) { return 0; }
        @Override public void beginTransaction() {}
        @Override public void beginTransaction(TransactionIsolation isolation, boolean readOnly) {}
        @Override public void commit() {}
        @Override public void rollback() {}
        @Override public boolean inTransaction() { return true; }
        @Override public boolean isOpen() { return true; }
        @Override public void close() {}
    }

    private static final class CapturingStatement implements PersistenceStatement {
        final String sql;
        final CapturingTransactionalExecutor executor;
        final Map<Integer, Object> boundParameters = new HashMap<>();

        CapturingStatement(String sql, CapturingTransactionalExecutor executor) {
            this.sql = sql;
            this.executor = executor;
        }

        @Override public PersistenceStatement bindInt(int index, int value) { boundParameters.put(index, value); return this; }
        @Override public PersistenceStatement bindLong(int index, long value) { boundParameters.put(index, value); return this; }
        @Override public PersistenceStatement bindShort(int index, short value) { boundParameters.put(index, value); return this; }
        @Override public PersistenceStatement bindFloat(int index, float value) { boundParameters.put(index, value); return this; }
        @Override public PersistenceStatement bindDouble(int index, double value) { boundParameters.put(index, value); return this; }
        @Override public PersistenceStatement bindBoolean(int index, boolean value) { boundParameters.put(index, value); return this; }
        @Override public PersistenceStatement bindString(int index, String value) { boundParameters.put(index, value); return this; }
        @Override public PersistenceStatement bindUuid(int index, UUID value) { boundParameters.put(index, value); return this; }
        @Override public PersistenceStatement bindBytes(int index, byte[] value) { boundParameters.put(index, value); return this; }
        @Override public PersistenceStatement bindInstant(int index, Instant value) { boundParameters.put(index, value); return this; }
        @Override public PersistenceStatement bindNull(int index) { boundParameters.put(index, null); return this; }

        @Override
        public QueryResult executeQuery() {
            if (executor.queryResultSupplier != null) {
                return executor.queryResultSupplier.get();
            }
            return new StubQueryResult(List.of());
        }

        @Override
        public long executeUpdate() {
            return executor.rowsAffectedResult;
        }

        @Override
        public void close() {}
    }

    private static final class StubQueryResult implements QueryResult {
        private final List<Object[]> rows;
        private int cursor = -1;

        StubQueryResult(List<Object[]> rows) {
            this.rows = rows;
        }

        @Override
        public boolean next() {
            cursor++;
            return cursor < rows.size();
        }

        @Override
        public RowCursor row() {
            return new StubRowCursor(rows.get(cursor));
        }

        @Override public long rowsAffected() { return rows.size(); }
        @Override public int columnCount() { return rows.isEmpty() ? 0 : rows.get(0).length; }
        @Override public String commandTag() { return "SELECT"; }
        @Override public void close() {}
    }

    private static final class StubRowCursor implements RowCursor {
        private final Object[] values;

        StubRowCursor(Object[] values) {
            this.values = values;
        }

        @Override public boolean isNull(int index) { return values[index] == null; }
        @Override public int getInt(int index) { return (Integer) values[index]; }
        @Override public long getLong(int index) { return (Long) values[index]; }
        @Override public short getShort(int index) { return (Short) values[index]; }
        @Override public float getFloat(int index) { return (Float) values[index]; }
        @Override public double getDouble(int index) { return (Double) values[index]; }
        @Override public boolean getBoolean(int index) { return (Boolean) values[index]; }
        @Override public String getString(int index) { return (String) values[index]; }
        @Override public UUID getUuid(int index) { return (UUID) values[index]; }
        @Override public byte[] getBytes(int index) { return (byte[]) values[index]; }
        @Override public Instant getInstant(int index) { return (Instant) values[index]; }
        @Override public java.lang.foreign.MemorySegment getSegment(int index) { return null; }
        @Override public int getLength(int index) { return 0; }
        @Override public int columnCount() { return values.length; }
        @Override public boolean isValid() { return true; }
    }
}
