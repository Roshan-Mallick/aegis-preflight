package aegis.audit;

import aegis.preflight.Finding;
import aegis.preflight.Verdict;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

public class IncidentReportStore implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(IncidentReportStore.class);
    private static final Gson gson = new GsonBuilder().setPrettyPrinting().create();

    private final Connection connection;

    public IncidentReportStore(String dbPath) throws AuditException {
        try {
            this.connection = DriverManager.getConnection("jdbc:sqlite:" + dbPath);
            initializeSchema();
            log.info("IncidentReportStore initialized: {}", dbPath);
        } catch (SQLException e) {
            throw new AuditException("Failed to open incident report database: " + dbPath, e);
        }
    }

    public IncidentReportStore(Connection connection) throws AuditException {
        this.connection = connection;
        initializeSchema();
    }

    private void initializeSchema() throws AuditException {
        String sql = """
            CREATE TABLE IF NOT EXISTS incident_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                verdict TEXT NOT NULL,
                findings_json TEXT NOT NULL,
                agent_command TEXT,
                round_number INTEGER,
                developer_note TEXT,
                evidence_files_json TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_incident_timestamp
                ON incident_reports(timestamp);
            CREATE INDEX IF NOT EXISTS idx_incident_verdict
                ON incident_reports(verdict);
            """;

        try (Statement stmt = connection.createStatement()) {
            stmt.execute(sql);
        } catch (SQLException e) {
            throw new AuditException("Failed to initialize incident report schema", e);
        }
    }

    public void save(IncidentReport report) throws AuditException {
        String sql = """
            INSERT INTO incident_reports
                (timestamp, verdict, findings_json, agent_command,
                 round_number, developer_note, evidence_files_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """;

        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, report.timestamp().toString());
            stmt.setString(2, report.verdict().name());
            stmt.setString(3, gson.toJson(report.findings()));
            stmt.setString(4, report.agentCommand());
            stmt.setInt(5, report.roundNumber());
            stmt.setString(6, report.developerNote());
            stmt.setString(7, gson.toJson(report.evidenceFiles()));
            stmt.executeUpdate();
            log.info("Incident report saved: {}", report.summary());
        } catch (SQLException e) {
            throw new AuditException("Failed to save incident report", e);
        }
    }

    public List<IncidentReport> queryRecent(int limit) throws AuditException {
        String sql = "SELECT * FROM incident_reports ORDER BY timestamp DESC LIMIT ?";
        List<IncidentReport> reports = new ArrayList<>();

        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setInt(1, limit);
            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                reports.add(mapRow(rs));
            }
        } catch (SQLException e) {
            throw new AuditException("Failed to query recent incident reports", e);
        }
        return reports;
    }

    public List<IncidentReport> queryByVerdict(Verdict verdict) throws AuditException {
        String sql = "SELECT * FROM incident_reports WHERE verdict = ? ORDER BY timestamp DESC";
        List<IncidentReport> reports = new ArrayList<>();

        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, verdict.name());
            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                reports.add(mapRow(rs));
            }
        } catch (SQLException e) {
            throw new AuditException("Failed to query incident reports by verdict", e);
        }
        return reports;
    }

    public List<IncidentReport> queryByTimeRange(Instant from, Instant to) throws AuditException {
        String sql = "SELECT * FROM incident_reports WHERE timestamp BETWEEN ? AND ? ORDER BY timestamp DESC";
        List<IncidentReport> reports = new ArrayList<>();

        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, from.toString());
            stmt.setString(2, to.toString());
            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                reports.add(mapRow(rs));
            }
        } catch (SQLException e) {
            throw new AuditException("Failed to query incident reports by time range", e);
        }
        return reports;
    }

    public int count() throws AuditException {
        String sql = "SELECT COUNT(*) FROM incident_reports";
        try (Statement stmt = connection.createStatement()) {
            ResultSet rs = stmt.executeQuery(sql);
            if (rs.next()) {
                return rs.getInt(1);
            }
        } catch (SQLException e) {
            throw new AuditException("Failed to count incident reports", e);
        }
        return 0;
    }

    private IncidentReport mapRow(ResultSet rs) throws SQLException {
        Instant timestamp = Instant.parse(rs.getString("timestamp"));
        Verdict verdict = Verdict.valueOf(rs.getString("verdict"));
        String findingsJson = rs.getString("findings_json");
        String agentCommand = rs.getString("agent_command");
        int roundNumber = rs.getInt("round_number");
        String developerNote = rs.getString("developer_note");
        String evidenceFilesJson = rs.getString("evidence_files_json");

        List<Finding> findings = gson.fromJson(findingsJson,
            new TypeToken<List<Finding>>() {}.getType());

        List<String> evidenceFiles = gson.fromJson(evidenceFilesJson,
            new TypeToken<List<String>>() {}.getType());

        return new IncidentReport(
            timestamp, verdict, findings, agentCommand,
            roundNumber, developerNote, evidenceFiles
        );
    }

    @Override
    public void close() throws AuditException {
        try {
            if (connection != null && !connection.isClosed()) {
                connection.close();
                log.info("IncidentReportStore closed");
            }
        } catch (SQLException e) {
            throw new AuditException("Failed to close incident report database", e);
        }
    }
}
