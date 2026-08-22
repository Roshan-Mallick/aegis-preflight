package aegis.audit;

import aegis.preflight.Finding;
import aegis.preflight.ScanResult;
import aegis.preflight.Verdict;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

/**
 * Facade over the hash-chained {@link AuditStore}.
 *
 * Every gate decision (sandbox start/stop, agent run, BLOCK, PASS,
 * fix-applied, rescan, release, override) is persisted as one row of the
 * tamper-evident chain.
 */
public class AuditLogger implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(AuditLogger.class);
    private static final Gson gson = new GsonBuilder().disableHtmlEscaping().create();

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

    // --- Sandbox gate ---

    public void logSandboxStart(String containerName, String workspace, String networkPolicy) throws AuditException {
        auditStore.writeEvent(AuditEvent.info(
            AuditEvent.EventType.SANDBOX_START,
            "SandboxManager",
            "Sandbox started (entry gate)",
            String.format("container=%s workspace=%s network=%s", containerName, workspace, networkPolicy)
        ));
    }

    public void logSandboxStop(String containerName) throws AuditException {
        auditStore.writeEvent(AuditEvent.info(
            AuditEvent.EventType.SANDBOX_STOP,
            "SandboxManager",
            "Sandbox stopped",
            "container=" + containerName
        ));
    }

    public void logSandboxKill(String containerName, String reason) throws AuditException {
        auditStore.writeEvent(AuditEvent.warn(
            AuditEvent.EventType.SANDBOX_KILL,
            "SandboxManager",
            "Sandbox killed: " + reason,
            "container=" + containerName
        ));
    }

    public void logNetworkRevoked(String containerName) throws AuditException {
        auditStore.writeEvent(AuditEvent.warn(
            AuditEvent.EventType.SANDBOX_REVOKE_NETWORK,
            "SandboxManager",
            "Network access revoked",
            "container=" + containerName
        ));
    }

    // --- Agent activity ---

    public void logAgentRun(String command, int exitCode, int filesAdded, int filesModified,
                            long durationMs) throws AuditException {
        auditStore.writeEvent(AuditEvent.info(
            AuditEvent.EventType.AGENT_RUN,
            "AgentRunner",
            "Agent execution completed",
            String.format("command=%s exit=%d added=%d modified=%d duration=%dms",
                abbreviate(command), exitCode, filesAdded, filesModified, durationMs)
        ));
    }

    public void logFixApplied(int round, String summary) throws AuditException {
        auditStore.writeEvent(AuditEvent.info(
            AuditEvent.EventType.FIX_APPLIED,
            "RemediationLoop",
            "Agent signalled fix applied",
            "round=" + round + (summary == null || summary.isBlank() ? "" : " summary=" + abbreviate(summary))
        ));
    }

    // --- PreFlight gate ---

    public void logScanComplete(ScanResult result) throws AuditException {
        AuditEvent.Severity severity = switch (result.getVerdict()) {
            case PASS -> AuditEvent.Severity.INFO;
            case WARNING -> AuditEvent.Severity.WARNING;
            case BLOCK -> AuditEvent.Severity.CRITICAL;
        };

        String findingsJson = gson.toJson(result.getFindings().stream()
            .map(f -> new FindingSnapshot(f.type().name(), f.severity().name(), f.file(), f.line()))
            .toList());

        auditStore.writeEvent(AuditEvent.unchained(
            AuditEvent.EventType.SCAN_COMPLETE,
            severity,
            result.getScannerName(),
            String.format("Scan completed: %s (%d findings)", result.getVerdict(), result.findingCount()),
            "duration=" + result.getDuration().toMillis() + "ms available=" + result.isScannerAvailable()
                + " findings=" + findingsJson
        ));
    }

    public void logFinding(Finding finding, String tool) throws AuditException {
        AuditEvent.EventType type = switch (finding.type()) {
            case SECRET -> AuditEvent.EventType.FINDING_SECRET;
            case CVE -> AuditEvent.EventType.FINDING_CVE;
            case DEPENDENCY -> AuditEvent.EventType.FINDING_DEPENDENCY;
            case CONFIG -> AuditEvent.EventType.POLICY_VIOLATION;
            case SAST -> AuditEvent.EventType.POLICY_VIOLATION;
        };

        AuditEvent.Severity severity = switch (finding.severity()) {
            case CRITICAL -> AuditEvent.Severity.CRITICAL;
            case HIGH -> AuditEvent.Severity.ERROR;
            case MEDIUM -> AuditEvent.Severity.WARNING;
            default -> AuditEvent.Severity.INFO;
        };

        auditStore.writeEvent(AuditEvent.unchained(type, severity, tool,
            String.format("%s [%s] in %s:%d", finding.type(), finding.severity(),
                finding.file(), finding.line()),
            finding.remediation()
        ));
    }

    /**
     * The core gate decision row: BLOCK / WARNING / PASS for one scan round.
     */
    public AuditEvent logGateDecision(Verdict verdict, int round, List<Finding> blockers,
                                      List<Finding> warnings) throws AuditException {
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
        return auditStore.writeEvent(AuditEvent.unchained(type, severity, "RemediationLoop",
            verdict == Verdict.BLOCK ? "GATE DECISION: BLOCK" : "GATE DECISION: " + verdict,
            String.format("round=%d blockers=%d warnings=%d", round, blockers.size(), warnings.size())));
    }

    // --- Release / escalation ---

    public void logReleased(int round) throws AuditException {
        auditStore.writeEvent(AuditEvent.info(
            AuditEvent.EventType.RELEASED,
            "RemediationLoop",
            "Changes passed PreFlight and were released from sandbox to real filesystem",
            "round=" + round
        ));
    }

    public void logManualReview(int roundsUsed, List<Finding> unresolved) throws AuditException {
        auditStore.writeEvent(AuditEvent.critical(
            AuditEvent.EventType.MANUAL_REVIEW,
            "RemediationLoop",
            "Max remediation retries exhausted — escalated to manual review",
            String.format("rounds=%d unresolvedFindings=%d", roundsUsed, unresolved.size())
        ));
    }

    public void logDeveloperOverride(String user, String justification) throws AuditException {
        auditStore.writeEvent(AuditEvent.critical(
            AuditEvent.EventType.DEVELOPER_OVERRIDE,
            user == null ? "Developer" : user,
            "Manual override: blocked changes released despite findings",
            justification
        ));
    }

    public void logActivityFlagged(String kind, String detail, String reason) throws AuditException {
        auditStore.writeEvent(AuditEvent.warn(
            AuditEvent.EventType.ACTIVITY_FLAGGED,
            "ActivityMonitor",
            "Suspicious activity flagged: " + kind,
            String.format("detail=%s rule=%s", abbreviate(detail), reason)
        ));
    }

    // --- Guarded-terminal command gate ---

    /**
     * One hash-chained row per pre-execution CommandGate decision.
     * ALLOW -> COMMAND_ALLOWED, BLOCK -> TOOL_BLOCKED (the command never
     * reached docker exec), REQUIRE_APPROVAL -> APPROVAL_REQUESTED.
     */
    public void logCommandDecision(String command, aegis.policy.CommandDecision decision,
                                   String sessionId) throws AuditException {
        AuditEvent.EventType type = switch (decision) {
            case ALLOW -> AuditEvent.EventType.COMMAND_ALLOWED;
            case BLOCK -> AuditEvent.EventType.TOOL_BLOCKED;
            case REQUIRE_APPROVAL -> AuditEvent.EventType.APPROVAL_REQUESTED;
        };
        AuditEvent.Severity severity = switch (decision) {
            case ALLOW -> AuditEvent.Severity.INFO;
            case BLOCK -> AuditEvent.Severity.ERROR;
            case REQUIRE_APPROVAL -> AuditEvent.Severity.WARNING;
        };
        auditStore.writeEvent(new AuditEvent(
            -1, java.time.Instant.now(), type,
            AuditStore.payloadToJson(new AuditEvent.Payload(
                severity.name(),
                "CommandGate",
                "Command gate decision: " + decision.label(),
                String.format("session=%s command=%s reason=%s",
                    sessionId == null ? "-" : sessionId, abbreviate(command), decision.reason())
            )),
            null, null));
    }

    /** A human approved a held command; it is about to execute. */
    public void logApprovalGranted(String command, String user) throws AuditException {
        auditStore.writeEvent(AuditEvent.info(
            AuditEvent.EventType.APPROVAL_GRANTED,
            user == null || user.isBlank() ? "Operator" : user,
            "Security approval GRANTED — held command released for execution",
            "command=" + abbreviate(command)
        ));
    }

    /** A human denied a held command; it will never execute. */
    public void logApprovalDenied(String command, String user, String justification)
            throws AuditException {
        auditStore.writeEvent(AuditEvent.critical(
            AuditEvent.EventType.DEVELOPER_OVERRIDE,
            user == null || user.isBlank() ? "Operator" : user,
            "Security approval DENIED — command rejected before execution",
            String.format("justification=%s command=%s",
                justification == null || justification.isBlank() ? "(none)" : justification,
                abbreviate(command))
        ));
    }

    public void logChainVerified(AuditStore.ChainVerification verification) throws AuditException {
        auditStore.writeEvent(AuditEvent.info(
            AuditEvent.EventType.CHAIN_VERIFIED,
            "AuditViewer",
            verification.valid() ? "Chain integrity check PASSED" : "Chain integrity check TAMPERED",
            verification.message()
        ));
    }

    // --- Queries / accessors ---

    public List<AuditEvent> getRecentEvents(int limit) throws AuditException {
        return auditStore.queryRecent(limit);
    }

    public AuditStore.ChainVerification verifyChain() throws AuditException {
        return auditStore.verifyChain();
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

    private static String abbreviate(String s) {
        if (s == null) {
            return "";
        }
        return s.length() <= 120 ? s : s.substring(0, 117) + "...";
    }

    private record FindingSnapshot(String type, String severity, String file, int line) {
    }
}
