package aegis.audit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

public class AuditStore implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(AuditStore.class);
    private final Connection connection;

    public AuditStore(String dbPath) throws AuditException {
        try {
            this.connection = DriverManager.getConnection("jdbc:sqlite:" + dbPath);
            initializeSchema();
            log.info("AuditStore initialized: {}", dbPath);
        } catch (SQLException e) {
            throw new AuditException("Failed to open audit database: " + dbPath, e);
        }
    }

    public AuditStore(Connection connection) throws AuditException {
        this.connection = connection;
        initializeSchema();
    }

    private void initializeSchema() throws AuditException {
        String sql = """
            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                source TEXT NOT NULL,
                message TEXT NOT NULL,
                details TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_audit_timestamp
                ON audit_events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_audit_type
                ON audit_events(event_type);
            CREATE INDEX IF NOT EXISTS idx_audit_severity
                ON audit_events(severity);
            """;

        try (Statement stmt = connection.createStatement()) {
            stmt.execute(sql);
        } catch (SQLException e) {
            throw new AuditException("Failed to initialize audit schema", e);
        }
    }

    public void writeEvent(AuditEvent event) throws AuditException {
        String sql = """
            INSERT INTO audit_events (timestamp, event_type, severity, source, message, details)
            VALUES (?, ?, ?, ?, ?, ?)
            """;

        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, event.timestamp().toString());
            stmt.setString(2, event.type().name());
            stmt.setString(3, event.severity().name());
            stmt.setString(4, event.source());
            stmt.setString(5, event.message());
            stmt.setString(6, event.details());
            stmt.executeUpdate();
            log.debug("Audit event written: {}", event.type());
        } catch (SQLException e) {
            throw new AuditException("Failed to write audit event", e);
        }
    }

    public List<AuditEvent> queryByType(AuditEvent.EventType type) throws AuditException {
        String sql = "SELECT * FROM audit_events WHERE event_type = ? ORDER BY timestamp DESC";
        List<AuditEvent> events = new ArrayList<>();

        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, type.name());
            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                events.add(mapRow(rs));
            }
        } catch (SQLException e) {
            throw new AuditException("Failed to query audit events by type", e);
        }
        return events;
    }

    public List<AuditEvent> queryBySeverity(AuditEvent.Severity severity) throws AuditException {
        String sql = "SELECT * FROM audit_events WHERE severity = ? ORDER BY timestamp DESC";
        List<AuditEvent> events = new ArrayList<>();

        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, severity.name());
            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                events.add(mapRow(rs));
            }
        } catch (SQLException e) {
            throw new AuditException("Failed to query audit events by severity", e);
        }
        return events;
    }

    public List<AuditEvent> queryByTimeRange(Instant from, Instant to) throws AuditException {
        String sql = "SELECT * FROM audit_events WHERE timestamp BETWEEN ? AND ? ORDER BY timestamp DESC";
        List<AuditEvent> events = new ArrayList<>();

        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, from.toString());
            stmt.setString(2, to.toString());
            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                events.add(mapRow(rs));
            }
        } catch (SQLException e) {
            throw new AuditException("Failed to query audit events by time range", e);
        }
        return events;
    }

    public List<AuditEvent> queryRecent(int limit) throws AuditException {
        String sql = "SELECT * FROM audit_events ORDER BY timestamp DESC LIMIT ?";
        List<AuditEvent> events = new ArrayList<>();

        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setInt(1, limit);
            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                events.add(mapRow(rs));
            }
        } catch (SQLException e) {
            throw new AuditException("Failed to query recent audit events", e);
        }
        return events;
    }

    public int countBySeverity(AuditEvent.Severity severity) throws AuditException {
        String sql = "SELECT COUNT(*) FROM audit_events WHERE severity = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, severity.name());
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return rs.getInt(1);
            }
        } catch (SQLException e) {
            throw new AuditException("Failed to count audit events", e);
        }
        return 0;
    }

    private AuditEvent mapRow(ResultSet rs) throws SQLException {
        Instant timestamp = Instant.parse(rs.getString("timestamp"));
        AuditEvent.EventType type = AuditEvent.EventType.valueOf(rs.getString("event_type"));
        AuditEvent.Severity severity = AuditEvent.Severity.valueOf(rs.getString("severity"));
        String source = rs.getString("source");
        String message = rs.getString("message");
        String details = rs.getString("details");
        return new AuditEvent(timestamp, type, severity, source, message, details);
    }

    @Override
    public void close() throws AuditException {
        try {
            if (connection != null && !connection.isClosed()) {
                connection.close();
                log.info("AuditStore closed");
            }
        } catch (SQLException e) {
            throw new AuditException("Failed to close audit database", e);
        }
    }
}
