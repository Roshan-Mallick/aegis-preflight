package aegis.loop;

import aegis.audit.AuditException;
import aegis.audit.AuditLogger;
import aegis.monitor.ActivityEvent;
import aegis.preflight.Finding;
import aegis.preflight.ScanEngine;
import aegis.preflight.ScanResult;
import aegis.preflight.ScannerException;
import aegis.preflight.Verdict;
import aegis.sandbox.DockerSandbox;
import aegis.sandbox.SandboxManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.function.BiConsumer;

/**
 * GATE 2: PREFLIGHT remediation loop.
 *
 *   agent task -> scan -> [PASS] release
 *                     -> [BLOCK] write findings.json into workspace,
 *                        agent self-fixes, rescan automatically
 *                        (max 3 retries, then manual review state)
 *
 * Every gate decision (block, pass, fix-applied, release, escalation) is
 * persisted as one hash-chained audit row.
 */
public class RemediationLoop {

    private static final Logger log = LoggerFactory.getLogger(RemediationLoop.class);

    /** Hardcoded per spec for demo determinism. */
    public static final int MAX_RETRIES = 3;

    private static final String FINDINGS_FILE = "/workspace/findings.json";

    private final SandboxManager sandboxManager;
    private final AuditLogger audit;
    private final ScanEngine scanEngine;
    private final BiConsumer<LoopState, String> stateListener;

    public RemediationLoop(SandboxManager sandboxManager, AuditLogger audit,
                           BiConsumer<LoopState, String> stateListener) {
        this.sandboxManager = sandboxManager;
        this.audit = audit;
        this.scanEngine = new ScanEngine(sandboxManager.getWorkspace());
        this.stateListener = stateListener == null ? (s, d) -> { } : stateListener;
    }

    public enum LoopState {
        SANDBOXED,
        ISOLATION_PROBE,
        AGENT_RUNNING,
        SCANNING,
        BLOCKED,
        FIXING,
        RESCANNING,
        PASSED,
        RELEASED,
        MANUAL_REVIEW
    }

    private void state(LoopState s, String detail) {
        log.info("Loop state: {} ({})", s, detail);
        stateListener.accept(s, detail);
    }

    /**
     * DEMO-CRITICAL step 1 evidence: attempt operations outside the workspace
     * and network egress; both must fail inside the sandbox. Flagged events are
     * recorded by the ActivityMonitor and returned here for display.
     */
    public List<ActivityEvent> runIsolationProbe() {
        state(LoopState.ISOLATION_PROBE, "Probing sandbox isolation");

        // Filesystem outside /workspace (read-only rootfs must refuse)
        sandboxManager.exec(
            "touch /root/pwned-by-agent 2>&1; echo \"AEGIS-EVENT {\\\"kind\\\":\\\"file_access\\\","
                + "\\\"detail\\\":\\\"write /root/pwned-by-agent\\\"}\"");
        sandboxManager.exec(
            "cat /etc/shadow > /dev/null 2>&1; echo \"AEGIS-EVENT {\\\"kind\\\":\\\"file_access\\\","
                + "\\\"detail\\\":\\\"read /etc/shadow\\\"}\"");

        // Network egress (--network=none must make this fail fast)
        sandboxManager.exec(
            "timeout 3 bash -c 'echo > /dev/tcp/example.com/80' 2>&1; "
                + "echo \"AEGIS-EVENT {\\\"kind\\\":\\\"network_attempt\\\","
                + "\\\"detail\\\":\\\"tcp connect example.com:80\\\"}\"");

        List<ActivityEvent> flagged = new ArrayList<>();
        if (sandboxManager.getMonitor() != null) {
            sandboxManager.getMonitor().snapshotHistory().stream()
                .filter(ActivityEvent::flagged)
                .forEach(flagged::add);
        }
        return flagged;
    }

    /**
     * Full loop: initial agent task, then BLOCK -> fix -> rescan until PASS
     * or retries exhausted.
     */
    public LoopResult run(String taskCommand, String fixCommand, long agentTimeoutSeconds)
            throws ScannerException {

        long start = System.currentTimeMillis();
        List<RoundRecord> rounds = new ArrayList<>();
        Verdict finalVerdict = Verdict.BLOCK;

        for (int round = 1; round <= MAX_RETRIES + 1; round++) {
            boolean isInitialTask = round == 1;

            state(isInitialTask ? LoopState.AGENT_RUNNING : LoopState.FIXING,
                (isInitialTask ? "Running agent task" : "Agent self-fix round " + (round - 1))
                    + " in sandbox");

            String roundCommand = isInitialTask ? taskCommand : fixCommand;
            DockerSandbox.ExecOutcome outcome =
                sandboxManager.exec(roundCommand + " 2>&1; echo \"__AEGIS_EXIT__:$?\"");
            int exitCode = parseExitMarker(outcome.output());
            logAgentRun(roundCommand, exitCode, outcome);

            if (!isInitialTask && outcome.output() != null
                    && outcome.output().contains("FIX_APPLIED")) {
                try {
                    audit.logFixApplied(round - 1, "Agent self-fix applied from findings.json");
                } catch (AuditException e) {
                    log.error("Failed to persist fix-applied event: {}", e.getMessage());
                }
            }

            if (isInitialTask && exitCode != 0) {
                log.warn("Agent task exited non-zero ({}); continuing to scan anyway", exitCode);
            }

            // ---- PreFlight scan ----
            state(LoopState.SCANNING, "PreFlight scan round " + round);
            List<ScanResult> results = scanEngine.scanAll();
            auditScans(results);

            List<Finding> blockers = filterByVerdict(results, Verdict.BLOCK);
            List<Finding> warnings = filterByVerdict(results, Verdict.WARNING);
            Verdict verdict = computeVerdict(results);
            rounds.add(new RoundRecord(round, verdict, results, blockers, warnings));

            try {
                audit.logGateDecision(verdict, round, blockers, warnings);
            } catch (AuditException e) {
                log.error("Failed to persist gate decision: {}", e.getMessage());
            }

            state(verdict == Verdict.BLOCK ? LoopState.BLOCKED : LoopState.PASSED,
                "Round " + round + ": " + verdict + " (" + blockers.size() + " blockers)");

            if (verdict != Verdict.BLOCK) {
                finalVerdict = verdict;
                break;
            }

            // ---- BLOCK: feed findings back to the agent ----
            if (round <= MAX_RETRIES) {
                writeFindingsToWorkspace(results, round);
                state(LoopState.RESCANNING,
                    "findings.json delivered — re-invoking agent (retry " + round + "/" + MAX_RETRIES + ")");
            }
            finalVerdict = verdict;
        }

        long elapsed = System.currentTimeMillis() - start;
        boolean passed = finalVerdict != Verdict.BLOCK;
        RoundRecord last = rounds.get(rounds.size() - 1);

        if (passed) {
            // [PASS] -> release changes from sandbox to the real filesystem
            state(LoopState.RELEASED, "Changes released from sandbox to real filesystem");
            try {
                audit.logReleased(last.round());
            } catch (AuditException e) {
                log.error("Failed to persist release event: {}", e.getMessage());
            }
            return new LoopResult(finalVerdict, rounds, elapsed, true, false);
        }

        // [FAIL after max retries] -> developer shown findings, manual override option
        state(LoopState.MANUAL_REVIEW,
            "Max retries exhausted — developer review required (" + last.blockers().size()
                + " unresolved blockers)");
        try {
            audit.logManualReview(MAX_RETRIES, last.blockers());
        } catch (AuditException e) {
            log.error("Failed to persist manual-review event: {}", e.getMessage());
        }
        return new LoopResult(finalVerdict, rounds, elapsed, false, true);
    }

    private void writeFindingsToWorkspace(List<ScanResult> results, int round) {
        ScanEngine engine = new ScanEngine(sandboxManager.getWorkspace());
        String json = engine.buildFindingsJson(Verdict.BLOCK, round,
            filterByVerdict(results, Verdict.BLOCK));

        // base64 to survive quoting/heredoc edge cases in shell transport
        String b64 = java.util.Base64.getEncoder().encodeToString(json.getBytes());
        DockerSandbox.ExecOutcome w = sandboxManager.exec(
            "echo " + b64 + " | base64 -d > " + FINDINGS_FILE + " && echo FINDINGS_WRITTEN");

        if (!w.output().contains("FINDINGS_WRITTEN")) {
            log.warn("Failed to write findings.json into workspace: {}", w.output());
        } else {
            log.info("findings.json written to workspace (round {}, {} chars)", round, json.length());
        }
    }

    private void auditScans(List<ScanResult> results) {
        try {
            for (ScanResult r : results) {
                audit.logScanComplete(r);
                for (Finding f : r.getFindings()) {
                    audit.logFinding(f, r.getScannerName());
                }
            }
        } catch (AuditException e) {
            log.error("Failed to persist scan events: {}", e.getMessage());
        }
    }

    private void logAgentRun(String cmd, int exitCode, DockerSandbox.ExecOutcome outcome) {
        try {
            audit.logAgentRun(cmd, exitCode, countMarker(outcome.output(), "ADDED:"),
                countMarker(outcome.output(), "MODIFIED:"), 0);
        } catch (AuditException e) {
            log.warn("Failed to persist agent-run event: {}", e.getMessage());
        }
    }

    private int countMarker(String output, String marker) {
        if (output == null) {
            return 0;
        }
        int n = 0;
        int idx = 0;
        while ((idx = output.indexOf(marker, idx)) >= 0) {
            n++;
            idx += marker.length();
        }
        return n;
    }

    private int parseExitMarker(String output) {
        if (output == null) {
            return -1;
        }
        String marker = "__AEGIS_EXIT__:";
        int idx = output.lastIndexOf(marker);
        if (idx < 0) {
            return -1;
        }
        try {
            return Integer.parseInt(output.substring(idx + marker.length()).strip());
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    private List<Finding> filterByVerdict(List<ScanResult> results, Verdict v) {
        List<Finding> out = new ArrayList<>();
        for (Finding f : collect(results)) {
            if (f.toVerdict() == v) {
                out.add(f);
            }
        }
        return out;
    }

    private List<Finding> collect(List<ScanResult> results) {
        List<Finding> all = new ArrayList<>();
        for (ScanResult r : results) {
            all.addAll(r.getFindings());
        }
        return all;
    }

    private Verdict computeVerdict(List<ScanResult> results) {
        Verdict v = Verdict.PASS;
        for (ScanResult r : results) {
            if (!r.isScannerAvailable()) {
                continue;
            }
            v = v.mergeWith(r.getVerdict());
        }
        return v;
    }

    public record RoundRecord(int round, Verdict verdict, List<ScanResult> scanResults,
                              List<Finding> blockers, List<Finding> warnings) {
    }

    public record LoopResult(Verdict finalVerdict, List<RoundRecord> rounds, long durationMs,
                             boolean released, boolean manualReview) {

        public int totalBlockersSeen() {
            return rounds.stream().mapToInt(r -> r.blockers().size()).sum();
        }
    }
}
