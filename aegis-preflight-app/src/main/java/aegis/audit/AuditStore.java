package aegis.audit;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * SQLite-backed, hash-chained audit log.
 *
 * Table (per Aegis spec):
 *   audit_events(id, timestamp, event_type, payload_json, prev_hash, curr_hash)
 *
 *   curr_hash = SHA256(prev_hash + timestamp + event_type + payload_json)
 *
 * Every append is serialized and reads the previous row's curr_hash inside the
 * same critical section, so concurrent writers cannot fork the chain.
 */
public class AuditStore implements AutoCloseable {

    private static final Gson gson = new GsonBuilder().disableHtmlEscaping().create();

    private final Connection connection;
    private final Object chainLock = new Object();

    public AuditStore(String dbPath) throws AuditException {
        try {
            this.connection = DriverManager.getConnection("jdbc:sqlite:" + dbPath);
            try (Statement st = connection.createStatement()) {
                st.execute("PRAGMA journal_mode=WAL");
                st.execute("PRAGMA synchronous=FULL");
                // Multiple processes may legitimately run Aegis instances
                // sharing one audit DB; give contending writers time to
                // acquire the write lock instead of failing fast.
                st.execute("PRAGMA busy_timeout=10000");
            }
            initializeSchema();
        } catch (SQLException e) {
            throw new AuditException("Failed to open audit database: " + dbPath, e);
        }
    }

    public AuditStore(Connection connection) throws AuditException {
        this.connection = connection;
        initializeSchema();
    }

    private void initializeSchema() throws AuditException {
        try (Statement stmt = connection.createStatement()) {
            stmt.executeUpdate("""
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    prev_hash TEXT NOT NULL,
                    curr_hash TEXT NOT NULL
                )
                """);
            stmt.executeUpdate("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp)");
            stmt.executeUpdate("CREATE INDEX IF NOT EXISTS idx_audit_type ON audit_events(event_type)");
            migrateLegacySchemaIfNeeded();
        } catch (SQLException e) {
            throw new AuditException("Failed to initialize audit schema", e);
        }
    }

    /**
     * Pre-chain releases stored severity/source/message columns directly.
     * If such a table is found, upgrade it in place and rebuild the chain
     * over the preserved rows so history stays verifiable.
     */
    private void migrateLegacySchemaIfNeeded() throws SQLException, AuditException {
        try (ResultSet rs = connection.createStatement().executeQuery("PRAGMA table_info(audit_events)")) {
            List<String> cols = new ArrayList<>();
            while (rs.next()) {
                cols.add(rs.getString("name"));
            }
            if (cols.isEmpty() || cols.contains("curr_hash")) {
                return;
            }
        }

        try (Statement stmt = connection.createStatement()) {
            stmt.executeUpdate("ALTER TABLE audit_events ADD COLUMN payload_json TEXT NOT NULL DEFAULT '{}'");

            stmt.executeUpdate("""
                UPDATE audit_events SET payload_json = json_object(
                    'severity', COALESCE(severity, 'INFO'),
                    'source',   COALESCE(source, 'Aegis'),
                    'message',  COALESCE(message, ''),
                    'details',  details)
                """);
            stmt.executeUpdate("ALTER TABLE audit_events RENAME TO audit_events_legacy");
        }

        try (Statement stmt = connection.createStatement()) {
            stmt.executeUpdate("""
                CREATE TABLE audit_events_new (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    prev_hash TEXT NOT NULL,
                    curr_hash TEXT NOT NULL
                )
                """);
            stmt.executeUpdate("""
                INSERT INTO audit_events_new (id, timestamp, event_type, payload_json, prev_hash, curr_hash)
                SELECT id, timestamp, event_type, payload_json, '', ''
                FROM audit_events_legacy ORDER BY id
                """);
            stmt.executeUpdate("DROP TABLE audit_events_legacy");
            stmt.executeUpdate("ALTER TABLE audit_events_new RENAME TO audit_events");
        }

        rebuildChain();
    }

    /**
     * Recomputes prev_hash/curr_hash for every row in id order.
     * Used by legacy migration only — verification never mutates rows.
     */
    private void rebuildChain() throws AuditException {
        synchronized (chainLock) {
            try {
                List<long[]> ids = new ArrayList<>();
                try (ResultSet rs = connection.createStatement()
                        .executeQuery("SELECT id FROM audit_events ORDER BY id")) {
                    while (rs.next()) {
                        ids.add(new long[]{rs.getLong(1)});
                    }
                }
                String prev = HashChain.GENESIS_HASH;
                for (long[] idArr : ids) {
                    Row row = readRow(idArr[0]);
                    String curr = HashChain.computeHash(prev, row.timestamp(), row.eventType(), row.payloadJson());
                    try (PreparedStatement ps = connection.prepareStatement(
                            "UPDATE audit_events SET prev_hash=?, curr_hash=? WHERE id=?")) {
                        ps.setString(1, prev);
                        ps.setString(2, curr);
                        ps.setLong(3, idArr[0]);
                        ps.executeUpdate();
                    }
                    prev = curr;
                }
            } catch (SQLException e) {
                throw new AuditException("Failed to rebuild audit chain", e);
            }
        }
    }

    private record Row(long id, String timestamp, String eventType, String payloadJson,
                       String prevHash, String currHash) {
    }

    private Row readRow(long id) throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement(
                "SELECT id, timestamp, event_type, payload_json, prev_hash, curr_hash FROM audit_events WHERE id=?")) {
            ps.setLong(1, id);
            ResultSet rs = ps.executeQuery();
            if (!rs.next()) {
                throw new SQLException("Row not found: " + id);
            }
            return new Row(rs.getLong("id"), rs.getString("timestamp"), rs.getString("event_type"),
                    rs.getString("payload_json"), rs.getString("prev_hash"), rs.getString("curr_hash"));
        }
    }

    /**
     * Appends an event to the chain and returns the persisted row
     * (with id, prev_hash and curr_hash populated).
     *
     * The head-read + insert run inside a BEGIN IMMEDIATE transaction, so the
     * SQLite write lock is held across BOTH steps. This serializes appenders
     * ACROSS PROCESSES too (the in-JVM chainLock alone cannot — two Aegis
     * instances sharing one audit DB would otherwise read the same head and
     * fork the chain). Busy contention is retried with a small backoff.
     */
    public AuditEvent writeEvent(AuditEvent event) throws AuditException {
        synchronized (chainLock) {
            String timestamp = event.timestamp().toString();
            String eventType = event.eventType().name();
            String payloadJson = event.payloadJson();

            SQLException lastFailure = null;
            for (int attempt = 0; attempt < 25; attempt++) {
                boolean beganTxn = false;
                try (Statement txn = connection.createStatement()) {
                    txn.execute("BEGIN IMMEDIATE");
                    beganTxn = true;

                    String prevHash;
                    try (Statement st = connection.createStatement();
                         ResultSet rs = st.executeQuery(
                             "SELECT curr_hash FROM audit_events ORDER BY id DESC LIMIT 1")) {
                        prevHash = rs.next() ? rs.getString(1) : HashChain.GENESIS_HASH;
                    }

                    String currHash =
                        HashChain.computeHash(prevHash, timestamp, eventType, payloadJson);

                    PreparedStatement stmt = connection.prepareStatement("""
                        INSERT INTO audit_events (timestamp, event_type, payload_json,
                                                  prev_hash, curr_hash)
                        VALUES (?, ?, ?, ?, ?)
                        """);
                    stmt.setString(1, timestamp);
                    stmt.setString(2, eventType);
                    stmt.setString(3, payloadJson);
                    stmt.setString(4, prevHash);
                    stmt.setString(5, currHash);
                    stmt.executeUpdate();

                    long id;
                    try (Statement st = connection.createStatement();
                         ResultSet rs = st.executeQuery("SELECT last_insert_rowid()")) {
                        id = rs.next() ? rs.getLong(1) : -1;
                    }

                    txn.execute("COMMIT");
                    return new AuditEvent(id, event.timestamp(), event.eventType(),
                        payloadJson, prevHash, currHash);
                } catch (SQLException e) {
                    lastFailure = e;
                    if (beganTxn) {
                        try (Statement rollback = connection.createStatement()) {
                            rollback.execute("ROLLBACK");
                        } catch (SQLException ignored) {
                        }
                    }
                    // busy/locked -> brief backoff and re-read the fresh head
                    if (!isBusy(e)) {
                        break;
                    }
                    try {
                        Thread.sleep(20L * (attempt + 1));
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                }
            }
            throw new AuditException(
                "Failed to write chained audit event"
                    + (lastFailure == null ? "" : ": " + lastFailure.getMessage()),
                lastFailure);
        }
    }

    private static boolean isBusy(SQLException e) {
        String msg = String.valueOf(e.getMessage()).toLowerCase();
        return msg.contains("busy") || msg.contains("locked")
            || msg.contains("snapshot");
    }

    /**
     * Recomputes prev_hash/curr_hash for every stored row in id order.
     *
     * Tamper-evident logs must never repair silently: this exists ONLY as an
     * explicit operator action for known-benign damage such as a pre-fix
     * multi-process fork. Verification itself never mutates rows.
     */
    public void repairChain() throws AuditException {
        synchronized (chainLock) {
            rebuildChain();
        }
    }

    /**
     * Recomputes the full chain from genesis and compares every stored hash.
     * Detects any row that was edited, deleted or appended out of band.
     */
    public ChainVerification verifyChain() throws AuditException {
        synchronized (chainLock) {
            String expectedPrev = HashChain.GENESIS_HASH;
            int checked = 0;
            try (Statement st = connection.createStatement();
                 ResultSet rs = st.executeQuery(
                     "SELECT id, timestamp, event_type, payload_json, prev_hash, curr_hash "
                     + "FROM audit_events ORDER BY id")) {

                while (rs.next()) {
                    long id = rs.getLong("id");
                    String timestamp = rs.getString("timestamp");
                    String eventType = rs.getString("event_type");
                    String payloadJson = rs.getString("payload_json");
                    String prevHash = rs.getString("prev_hash");
                    String currHash = rs.getString("curr_hash");

                    if (!expectedPrev.equals(prevHash)) {
                        return ChainVerification.tampered(id, checked,
                            "Row %d links to wrong parent: expected prev_hash %s but found %s"
                                .formatted(id, abbreviate(expectedPrev), abbreviate(prevHash)));
                    }

                    String recomputed = HashChain.computeHash(prevHash, timestamp, eventType, payloadJson);
                    if (!recomputed.equals(currHash)) {
                        return ChainVerification.tampered(id, checked,
                            "Row %d content was modified: stored curr_hash %s does not match recomputed %s"
                                .formatted(id, abbreviate(currHash), abbreviate(recomputed)));
                    }

                    expectedPrev = currHash;
                    checked++;
                }
            } catch (SQLException e) {
                throw new AuditException("Chain verification failed to read audit log", e);
            }
            return ChainVerification.valid(checked);
        }
    }

    private static String abbreviate(String hash) {
        if (hash == null) {
            return "null";
        }
        return hash.length() <= 12 ? hash : hash.substring(0, 12) + "…";
    }

    public record ChainVerification(boolean valid, int entriesChecked, long brokenAtId, String message) {

        static ChainVerification valid(int entriesChecked) {
            return new ChainVerification(true, entriesChecked, -1,
                "Chain integrity verified: " + entriesChecked + " entries OK");
        }

        static ChainVerification tampered(long brokenAtId, int entriesChecked, String message) {
            return new ChainVerification(false, entriesChecked, brokenAtId, message);
        }

        @Override
        public String toString() {
            return (valid ? "PASS — " : "TAMPERED — ") + message;
        }
    }

    public List<AuditEvent> queryAll() throws AuditException {
        return queryRecent(Integer.MAX_VALUE);
    }

    public List<AuditEvent> queryRecent(int limit) throws AuditException {
        String sql = limit == Integer.MAX_VALUE
            ? "SELECT * FROM audit_events ORDER BY id"
            : "SELECT * FROM audit_events ORDER BY id DESC LIMIT " + limit;
        List<AuditEvent> events = new ArrayList<>();
        try (Statement stmt = connection.createStatement(); ResultSet rs = stmt.executeQuery(sql)) {
            while (rs.next()) {
                events.add(mapRow(rs));
            }
        } catch (SQLException e) {
            throw new AuditException("Failed to query audit events", e);
        }
        if (limit != Integer.MAX_VALUE) {
            java.util.Collections.reverse(events);
        }
        return events;
    }

    public long count() throws AuditException {
        try (Statement st = connection.createStatement();
             ResultSet rs = st.executeQuery("SELECT COUNT(*) FROM audit_events")) {
            return rs.next() ? rs.getLong(1) : 0;
        } catch (SQLException e) {
            throw new AuditException("Failed to count audit events", e);
        }
    }

    private static AuditEvent mapRow(ResultSet rs) throws SQLException {
        return new AuditEvent(
            rs.getLong("id"),
            Instant.parse(rs.getString("timestamp")),
            AuditEvent.EventType.valueOf(rs.getString("event_type")),
            rs.getString("payload_json"),
            rs.getString("prev_hash"),
            rs.getString("curr_hash")
        );
    }

    public static String payloadToJson(AuditEvent.Payload payload) {
        return gson.toJson(payload);
    }

    @Override
    public void close() throws AuditException {
        try {
            if (connection != null && !connection.isClosed()) {
                connection.close();
            }
        } catch (SQLException e) {
            throw new AuditException("Failed to close audit database", e);
        }
    }
}
