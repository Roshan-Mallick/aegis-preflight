package aegis.agent;

import aegis.preflight.Finding;
import aegis.preflight.ScanEngine;
import aegis.preflight.ScanResult;
import aegis.preflight.ScannerException;
import aegis.preflight.Verdict;
import aegis.preflight.VerdictEngine;
import aegis.sandbox.DockerSandbox;
import aegis.sandbox.SandboxException;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.function.BiConsumer;

public class AgentLoop {

    private static final Logger log = LoggerFactory.getLogger(AgentLoop.class);
    private static final int MAX_ROUNDS = 3;
    private static final String FINDINGS_FILE = "/workspace/findings.json";
    private static final Gson gson = new GsonBuilder().setPrettyPrinting().create();

    private final DockerSandbox sandbox;
    private final AgentRunner runner;
    private final ScanEngine scanEngine;

    public AgentLoop(DockerSandbox sandbox) {
        this.sandbox = sandbox;
        this.runner = new AgentRunner(sandbox);
        this.scanEngine = new ScanEngine(sandbox);
    }

    public LoopResult execute(String agentCommand, long agentTimeoutSeconds,
                              BiConsumer<RoundInfo, Integer> onRoundComplete) throws AgentException, ScannerException {
        Instant start = Instant.now();
        List<RoundRecord> records = new ArrayList<>();

        log.info("AgentLoop starting: command='{}', maxRounds={}", agentCommand, MAX_ROUNDS);

        for (int round = 1; round <= MAX_ROUNDS; round++) {
            log.info("=== Round {}/{} ===", round, MAX_ROUNDS);

            RunResult agentResult = runner.run(agentCommand, agentTimeoutSeconds);
            log.info("Agent run: status={}, exit={}, changes={}",
                agentResult.getStatus(), agentResult.getExitCode(), agentResult.totalChanges());

            List<ScanResult> scanResults = scanEngine.scanAll();
            VerdictEngine verdictEngine = VerdictEngine.fromScanResults(scanResults);
            Verdict verdict = verdictEngine.computeVerdict();

            List<Finding> blockers = verdictEngine.getBlockers();
            List<Finding> warnings = verdictEngine.getWarnings();

            RoundRecord record = new RoundRecord(
                round, agentResult, scanResults, verdict,
                blockers, warnings, verdictEngine.count()
            );
            records.add(record);

            RoundInfo info = new RoundInfo(
                round, verdict, blockers.size(), warnings.size(),
                agentResult.totalChanges()
            );
            if (onRoundComplete != null) {
                onRoundComplete.accept(info, round);
            }

            if (verdict != Verdict.BLOCK) {
                log.info("Loop complete on round {}: verdict={}", round, verdict);
                Duration elapsed = Duration.between(start, Instant.now());
                return new LoopResult(verdict, records, elapsed, true);
            }

            log.info("BLOCK on round {}, writing findings.json and re-invoking agent", round);
            writeFindingsFile(verdictEngine, round);

            if (round < MAX_ROUNDS) {
                String fixPrompt = buildFixPrompt(blockers, round);
                log.info("Re-invoking agent with fix prompt ({} chars)", fixPrompt.length());
                try {
                    RunResult fixResult = runner.run(fixPrompt, agentTimeoutSeconds);
                    log.info("Agent fix round {}: status={}", round, fixResult.getStatus());
                } catch (AgentException e) {
                    log.warn("Agent fix round {} failed: {}", round, e.getMessage());
                }
            }
        }

        List<ScanResult> finalScans = scanEngine.scanAll();
        VerdictEngine finalEngine = VerdictEngine.fromScanResults(finalScans);
        Verdict finalVerdict = finalEngine.computeVerdict();

        Duration elapsed = Duration.between(start, Instant.now());
        log.info("Loop exhausted after {} rounds: finalVerdict={}", MAX_ROUNDS, finalVerdict);

        return new LoopResult(finalVerdict, records, elapsed, false);
    }

    public LoopResult execute(String agentCommand) throws AgentException, ScannerException {
        return execute(agentCommand, 300, null);
    }

    private void writeFindingsFile(VerdictEngine engine, int round) {
        String json = engine.toSummaryJson(Verdict.BLOCK, round);
        String writeCmd = "cat > " + FINDINGS_FILE + " << 'AEGIS_EOF'\n"
            + json + "\nAEGIS_EOF";
        try {
            sandbox.execInContainer(writeCmd);
            log.info("Written findings.json to workspace ({} chars)", json.length());
        } catch (SandboxException e) {
            log.warn("Failed to write findings.json: {}", e.getMessage());
        }
    }

    private String buildFixPrompt(List<Finding> blockers, int round) {
        StringBuilder sb = new StringBuilder();
        sb.append("PreFlight security scan found BLOCKING issues on round ")
          .append(round).append(".\n");
        sb.append("Read /workspace/findings.json for the full list.\n\n");
        sb.append("Fix the following issues:\n\n");

        for (int i = 0; i < blockers.size(); i++) {
            Finding f = blockers.get(i);
            sb.append(i + 1).append(". ").append(f.type()).append(" in ")
              .append(f.file()).append(":").append(f.line()).append("\n");
            sb.append("   ").append(f.remediation()).append("\n\n");
        }

        sb.append("After fixing, verify your changes are correct.");
        return sb.toString();
    }

    public static class RoundInfo {
        private final int round;
        private final Verdict verdict;
        private final int blockerCount;
        private final int warningCount;
        private final int filesChanged;

        public RoundInfo(int round, Verdict verdict, int blockerCount,
                         int warningCount, int filesChanged) {
            this.round = round;
            this.verdict = verdict;
            this.blockerCount = blockerCount;
            this.warningCount = warningCount;
            this.filesChanged = filesChanged;
        }

        public int getRound() { return round; }
        public Verdict getVerdict() { return verdict; }
        public int getBlockerCount() { return blockerCount; }
        public int getWarningCount() { return warningCount; }
        public int getFilesChanged() { return filesChanged; }
    }

    public static class RoundRecord {
        private final int round;
        private final RunResult agentResult;
        private final List<ScanResult> scanResults;
        private final Verdict verdict;
        private final List<Finding> blockers;
        private final List<Finding> warnings;
        private final int totalFindings;

        public RoundRecord(int round, RunResult agentResult,
                           List<ScanResult> scanResults, Verdict verdict,
                           List<Finding> blockers, List<Finding> warnings,
                           int totalFindings) {
            this.round = round;
            this.agentResult = agentResult;
            this.scanResults = scanResults;
            this.verdict = verdict;
            this.blockers = blockers;
            this.warnings = warnings;
            this.totalFindings = totalFindings;
        }

        public int getRound() { return round; }
        public RunResult getAgentResult() { return agentResult; }
        public List<ScanResult> getScanResults() { return scanResults; }
        public Verdict getVerdict() { return verdict; }
        public List<Finding> getBlockers() { return blockers; }
        public List<Finding> getWarnings() { return warnings; }
        public int getTotalFindings() { return totalFindings; }
    }

    public static class LoopResult {
        private final Verdict finalVerdict;
        private final List<RoundRecord> rounds;
        private final Duration totalDuration;
        private final boolean passed;

        public LoopResult(Verdict finalVerdict, List<RoundRecord> rounds,
                          Duration totalDuration, boolean passed) {
            this.finalVerdict = finalVerdict;
            this.rounds = rounds;
            this.totalDuration = totalDuration;
            this.passed = passed;
        }

        public Verdict getFinalVerdict() { return finalVerdict; }
        public List<RoundRecord> getRounds() { return rounds; }
        public Duration getTotalDuration() { return totalDuration; }
        public boolean isPassed() { return passed; }

        public int totalRounds() { return rounds.size(); }

        public int totalBlockersAcrossRounds() {
            return rounds.stream().mapToInt(r -> r.getBlockers().size()).sum();
        }

        public String summary() {
            return String.format(
                "Final verdict: %s | Rounds: %d | Duration: %dms | Passed: %s",
                finalVerdict, totalRounds(), totalDuration.toMillis(), passed
            );
        }
    }
}
