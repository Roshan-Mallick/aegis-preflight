package aegis.audit;

import aegis.agent.AgentLoop;
import aegis.agent.RunResult;
import aegis.preflight.Finding;
import aegis.preflight.ScanResult;
import aegis.preflight.Verdict;
import aegis.sandbox.DockerSandbox;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class AuditLogger implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(AuditLogger.class);

    private final AuditStore auditStore;
    private final IncidentReportStore incidentStore;

    public AuditLogger(String dbPath) throws AuditException {
        this.auditStore = new AuditStore(dbPath);
        this.incidentStore = new IncidentReportStore(dbPath);
        log.info("AuditLogger initialized with db: {}", dbPath);
    }

    public AuditLogger(AuditStore auditStore, IncidentReportStore incidentStore) {
        this.auditStore = auditStore;
        this.incidentStore = incidentStore;
    }

    // --- Sandbox events ---

    public void logSandboxStart(String containerName, String workspace) throws AuditException {
        auditStore.writeEvent(AuditEvent.info(
            AuditEvent.EventType.SANDBOX_START,
            "DockerSandbox",
            "Sandbox started",
            String.format("container=%s workspace=%s", containerName, workspace)
        ));
    }

    public void logSandboxStop(String containerName) throws AuditException {
        auditStore.writeEvent(AuditEvent.info(
            AuditEvent.EventType.SANDBOX_STOP,
            "DockerSandbox",
            "Sandbox stopped",
            "container=" + containerName
        ));
    }

    public void logNetworkRevoked(String containerName) throws AuditException {
        auditStore.writeEvent(AuditEvent.warn(
            AuditEvent.EventType.SANDBOX_REVOKE_NETWORK,
            "DockerSandbox",
            "Network access revoked",
            "container=" + containerName
        ));
    }

    // --- Agent events ---

    public void logAgentRun(String command, RunResult result) throws AuditException {
        AuditEvent.EventType type = switch (result.getStatus()) {
            case SUCCESS -> AuditEvent.EventType.AGENT_RUN;
            case FAILED, AGENT_ERROR, CONTAINER_ERROR -> AuditEvent.EventType.AGENT_RUN;
            case TIMEOUT -> AuditEvent.EventType.AGENT_RUN;
        };

        AuditEvent.Severity severity = switch (result.getStatus()) {
            case SUCCESS -> AuditEvent.Severity.INFO;
            case TIMEOUT -> AuditEvent.Severity.WARNING;
            default -> AuditEvent.Severity.ERROR;
        };

        String details = String.format(
            "status=%s exit=%d added=%d modified=%d deleted=%d duration=%dms",
            result.getStatus(), result.getExitCode(),
            result.getAdded().size(), result.getModified().size(),
            result.getDeleted().size(), result.getDuration().toMillis()
        );

        auditStore.writeEvent(new AuditEvent(
            Instant.now(), type, severity,
            "AgentRunner", "Agent execution completed", details
        ));
    }

    public void logAgentFixAttempt(int round, String findings) throws AuditException {
        auditStore.writeEvent(AuditEvent.info(
            AuditEvent.EventType.AGENT_FIX_ATTEMPT,
            "AgentLoop",
            "Agent fix attempt initiated",
            String.format("round=%d findings=%d chars", round, findings.length())
        ));
    }

    // --- Scan events ---

    public void logScanStart(String scannerName) throws AuditException {
        auditStore.writeEvent(AuditEvent.info(
            AuditEvent.EventType.SCAN_START,
            scannerName,
            "Scan started"
        ));
    }

    public void logScanComplete(ScanResult result) throws AuditException {
        AuditEvent.Severity severity = switch (result.getVerdict()) {
            case PASS -> AuditEvent.Severity.INFO;
            case WARNING -> AuditEvent.Severity.WARNING;
            case BLOCK -> AuditEvent.Severity.CRITICAL;
        };

        auditStore.writeEvent(new AuditEvent(
            Instant.now(),
            AuditEvent.EventType.SCAN_COMPLETE,
            severity,
            result.getScannerName(),
            String.format("Scan completed: %s", result.getVerdict()),
            String.format("findings=%d duration=%dms available=%s",
                result.findingCount(), result.getDuration().toMillis(),
                result.isScannerAvailable())
        ));
    }

    public void logVerdict(Verdict verdict, List<Finding> findings) throws AuditException {
        AuditEvent.EventType type = switch (verdict) {
            case PASS -> AuditEvent.EventType.VERDICT_PASS;
            case WARNING -> AuditEvent.EventType.VERDICT_WARNING;
            case BLOCK -> AuditEvent.EventType.VERDICT_BLOCK;
        };

        AuditEvent.Severity severity = switch (verdict) {
            case PASS -> AuditEvent.Severity.INFO;
            case WARNING -> AuditEvent.Severity.WARNING;
            case BLOCK -> AuditEvent.Severity.CRITICAL;
        };

        String details = String.format("totalFindings=%d", findings.size());
        auditStore.writeEvent(new AuditEvent(
            Instant.now(), type, severity,
            "VerdictEngine",
            String.format("Overall verdict: %s", verdict),
            details
        ));
    }

    public void logFinding(Finding finding) throws AuditException {
        AuditEvent.EventType type = switch (finding.type()) {
            case SECRET -> AuditEvent.EventType.FINDING_SECRET;
            case CVE -> AuditEvent.EventType.FINDING_CVE;
            case DEPENDENCY -> AuditEvent.EventType.FINDING_DEPENDENCY;
            case CONFIG -> AuditEvent.EventType.POLICY_VIOLATION;
            case VULN -> AuditEvent.EventType.FINDING_CVE;
        };

        auditStore.writeEvent(AuditEvent.warn(type, "ScanEngine",
            String.format("%s in %s:%d — %s",
                finding.type(), finding.file(), finding.line(), finding.severity()),
            finding.remediation()
        ));
    }

    // --- Incident reports ---

    public void createIncidentReport(Verdict verdict, List<ScanResult> scanResults,
                                      String agentCommand, int round,
                                      Map<Path, String> evidenceFiles) throws AuditException {
        List<Finding> allFindings = new ArrayList<>();
        for (ScanResult result : scanResults) {
            allFindings.addAll(result.getFindings());
        }

        List<String> evidencePaths = evidenceFiles != null
            ? evidenceFiles.keySet().stream().map(Path::toString).toList()
            : List.of();

        IncidentReport report = new IncidentReport(
            Instant.now(), verdict, allFindings,
            agentCommand, round, null, evidencePaths
        );

        incidentStore.save(report);

        auditStore.writeEvent(AuditEvent.critical(
            AuditEvent.EventType.INCIDENT_REPORTED,
            "AuditLogger",
            report.summary(),
            String.format("findings=%d evidence=%d", allFindings.size(), evidencePaths.size())
        ));

        log.info("Incident report created: {}", report.summary());
    }

    public void createIncidentReport(Verdict verdict, List<Finding> findings,
                                      String developerNote) throws AuditException {
        IncidentReport report = new IncidentReport(
            Instant.now(), verdict, findings,
            null, 0, developerNote, List.of()
        );

        incidentStore.save(report);

        auditStore.writeEvent(AuditEvent.critical(
            AuditEvent.EventType.INCIDENT_REPORTED,
            "Developer",
            "Developer-triggered incident report",
            String.format("findings=%d note=%s", findings.size(), developerNote)
        ));
    }

    // --- Query methods ---

    public List<AuditEvent> getRecentEvents(int limit) throws AuditException {
        return auditStore.queryRecent(limit);
    }

    public List<AuditEvent> getEventsBySeverity(AuditEvent.Severity severity) throws AuditException {
        return auditStore.queryBySeverity(severity);
    }

    public List<IncidentReport> getRecentIncidents(int limit) throws AuditException {
        return incidentStore.queryRecent(limit);
    }

    public int getCriticalEventCount() throws AuditException {
        return auditStore.countBySeverity(AuditEvent.Severity.CRITICAL);
    }

    public int getIncidentCount() throws AuditException {
        return incidentStore.count();
    }

    public AuditStore getAuditStore() {
        return auditStore;
    }

    public IncidentReportStore getIncidentStore() {
        return incidentStore;
    }

    @Override
    public void close() throws AuditException {
        auditStore.close();
        incidentStore.close();
        log.info("AuditLogger closed");
    }
}
