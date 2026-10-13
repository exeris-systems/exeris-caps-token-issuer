package eu.exeris.caps.tokenissuer.testing;

import eu.exeris.kernel.spi.persistence.PersistenceConnection;
import eu.exeris.kernel.spi.persistence.PersistenceStatement;
import eu.exeris.kernel.spi.persistence.QueryResult;
import eu.exeris.kernel.spi.persistence.RowCursor;
import eu.exeris.kernel.spi.persistence.TransactionIsolation;
import eu.exeris.kernel.spi.persistence.TransactionalExecutor;

import java.lang.foreign.MemorySegment;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.UUID;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A plain-JDBC {@link TransactionalExecutor} for integration tests: one connection per unit of
 * work, {@code $n} placeholders rewritten to JDBC {@code ?}, zero-based binds shifted to one-based.
 */
public final class JdbcTransactionalExecutor implements TransactionalExecutor {

    private static final Pattern PLACEHOLDER = Pattern.compile("\\$(\\d+)");

    private final String url;
    private final String user;
    private final String password;

    public JdbcTransactionalExecutor(String url, String user, String password) {
        this.url = url;
        this.user = user;
        this.password = password;
    }

    public Connection open() throws SQLException {
        return DriverManager.getConnection(url, user, password);
    }

    @Override
    public void execute(TransactionalWork work) {
        executeManaged(work);
    }

    @Override
    public void executeManaged(TransactionalWork work) {
        try (Connection c = open()) {
            c.setAutoCommit(false);
            try {
                work.run(new JdbcConnection(c));
                c.commit();
            } catch (RuntimeException e) {
                c.rollback();
                throw e;
            }
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public void executeManaged(TransactionIsolation isolation, boolean readOnly, TransactionalWork work) {
        executeManaged(work);
    }

    @Override
    public <T> T query(Function<PersistenceConnection, T> query) {
        try (Connection c = open()) {
            return query.apply(new JdbcConnection(c));
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
    }

    private record JdbcConnection(Connection c) implements PersistenceConnection {
        @Override
        public PersistenceStatement prepare(String sql) {
            Matcher m = PLACEHOLDER.matcher(sql);
            try {
                return new JdbcStatement(c.prepareStatement(m.replaceAll("?")));
            } catch (SQLException e) {
                throw new IllegalStateException(e);
            }
        }

        @Override public QueryResult executeQuery(String sql) { return prepare(sql).executeQuery(); }
        @Override public long executeUpdate(String sql) { return prepare(sql).executeUpdate(); }
        @Override public void beginTransaction() { }
        @Override public void beginTransaction(TransactionIsolation isolation, boolean readOnly) { }
        @Override public void commit() { }
        @Override public void rollback() { }
        @Override public boolean inTransaction() { return true; }
        @Override public boolean isOpen() { return true; }
        @Override public void close() { }
    }

    private record JdbcStatement(PreparedStatement ps) implements PersistenceStatement {
        private PersistenceStatement bind(int index, Object value, int sqlType) {
            try {
                if (value == null) {
                    ps.setNull(index + 1, sqlType);
                } else {
                    ps.setObject(index + 1, value);
                }
                return this;
            } catch (SQLException e) {
                throw new IllegalStateException(e);
            }
        }

        @Override public PersistenceStatement bindInt(int i, int v) { return bind(i, v, Types.INTEGER); }
        @Override public PersistenceStatement bindLong(int i, long v) { return bind(i, v, Types.BIGINT); }
        @Override public PersistenceStatement bindShort(int i, short v) { return bind(i, v, Types.SMALLINT); }
        @Override public PersistenceStatement bindFloat(int i, float v) { return bind(i, v, Types.REAL); }
        @Override public PersistenceStatement bindDouble(int i, double v) { return bind(i, v, Types.DOUBLE); }
        @Override public PersistenceStatement bindBoolean(int i, boolean v) { return bind(i, v, Types.BOOLEAN); }
        @Override public PersistenceStatement bindString(int i, String v) { return bind(i, v, Types.VARCHAR); }
        @Override public PersistenceStatement bindUuid(int i, UUID v) { return bind(i, v, Types.OTHER); }
        @Override public PersistenceStatement bindBytes(int i, byte[] v) { return bind(i, v, Types.BINARY); }
        @Override public PersistenceStatement bindInstant(int i, Instant v) {
            return bind(i, v == null ? null : OffsetDateTime.ofInstant(v, ZoneOffset.UTC), Types.TIMESTAMP_WITH_TIMEZONE);
        }
        @Override public PersistenceStatement bindNull(int i) { return bind(i, null, Types.NULL); }

        @Override
        public QueryResult executeQuery() {
            try {
                return new JdbcResult(ps.executeQuery());
            } catch (SQLException e) {
                throw new IllegalStateException(e);
            }
        }

        @Override
        public long executeUpdate() {
            try {
                return ps.executeUpdate();
            } catch (SQLException e) {
                throw new IllegalStateException(e);
            }
        }

        @Override
        public void close() {
            try {
                ps.close();
            } catch (SQLException e) {
                throw new IllegalStateException(e);
            }
        }
    }

    private record JdbcResult(ResultSet rs) implements QueryResult, RowCursor {
        private <T> T get(SqlGetter<T> getter) {
            try {
                return getter.get();
            } catch (SQLException e) {
                throw new IllegalStateException(e);
            }
        }

        @Override public boolean next() { return get(rs::next); }
        @Override public RowCursor row() { return this; }
        @Override public long rowsAffected() { return 0; }
        @Override public int columnCount() { return get(() -> rs.getMetaData().getColumnCount()); }
        @Override public String commandTag() { return "SELECT"; }
        @Override public void close() { get(() -> { rs.close(); return null; }); }

        @Override public int getInt(int i) { return get(() -> rs.getInt(i + 1)); }
        @Override public long getLong(int i) { return get(() -> rs.getLong(i + 1)); }
        @Override public short getShort(int i) { return get(() -> rs.getShort(i + 1)); }
        @Override public float getFloat(int i) { return get(() -> rs.getFloat(i + 1)); }
        @Override public double getDouble(int i) { return get(() -> rs.getDouble(i + 1)); }
        @Override public boolean getBoolean(int i) { return get(() -> rs.getBoolean(i + 1)); }
        @Override public boolean isNull(int i) { return get(() -> { rs.getObject(i + 1); return rs.wasNull(); }); }
        @Override public MemorySegment getSegment(int i) { throw new UnsupportedOperationException(); }
        @Override public int getLength(int i) { throw new UnsupportedOperationException(); }
        @Override public String getString(int i) { return get(() -> rs.getString(i + 1)); }
        @Override public byte[] getBytes(int i) { return get(() -> rs.getBytes(i + 1)); }
        @Override public UUID getUuid(int i) { return get(() -> rs.getObject(i + 1, UUID.class)); }
        @Override public Instant getInstant(int i) {
            return get(() -> {
                OffsetDateTime t = rs.getObject(i + 1, OffsetDateTime.class);
                return t == null ? null : t.toInstant();
            });
        }
        @Override public boolean isValid() { return true; }
    }

    @FunctionalInterface
    private interface SqlGetter<T> {
        T get() throws SQLException;
    }
}
