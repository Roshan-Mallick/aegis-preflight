package aegis.preflight;

import aegis.agent.AgentRunner;
import aegis.agent.RunResult;
import aegis.sandbox.DockerSandbox;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.function.BiConsumer;

public class ScanEngine {

    private static final Logger log = LoggerFactory.getLogger(ScanEngine.class);
    private static final int MAX_FIX_ATTEMPTS = 3;

    private final DockerSandbox sandbox;
    private final GitleaksScanner gitleaks;
    private final DependencyScanner dependency;

    public ScanEngine(DockerSandbox sandbox) {
        this.sandbox = sandbox;
        this.gitleaks = new GitleaksScanner(sandbox);
        this.dependency = new DependencyScanner(sandbox);
    }

    public List<ScanResult> scanAll() throws ScannerException {
        List<ScanResult> results = new ArrayList<>();

        ScanResult gitleaksResult = gitleaks.scan();
        results.add(gitleaksResult);

        ScanResult depResult = dependency.scan();
        results.add(depResult);

        return results;
    }

    public Verdict computeOverallVerdict(List<ScanResult> results) {
        Verdict verdict = Verdict.PASS;
        for (ScanResult result : results) {
            verdict = verdict.mergeWith(result.getVerdict());
        }
        return verdict;
    }

    public List<Finding> collectAllFindings(List<ScanResult> results) {
        List<Finding> allFindings = new ArrayList<>();
        for (ScanResult result : results) {
            allFindings.addAll(result.getFindings());
        }
        return allFindings;
    }

    public String formatFindingsForAgent(List<ScanResult> results) {
        StringBuilder sb = new StringBuilder();
        sb.append("PREFLIGHT SCAN RESULTS\n");
        sb.append("======================\n\n");

        for (ScanResult result : results) {
            if (!result.isScannerAvailable()) {
                sb.append(result.getScannerName())
                  .append(": SKIPPED (not installed)\n\n");
                continue;
            }

            sb.append(result.getScannerName())
              .append(": ").append(result.getVerdict())
              .append(" (").append(result.findingCount()).append(" findings)\n");

            if (result.hasBlockers()) {
                sb.append("ACTION REQUIRED: Fix the following issues:\n\n");
                int i = 1;
                for (Finding f : result.getBlockers()) {
                    sb.append(i++).append(". ").append(f.type())
                      .append(" / ").append(f.severity()).append("\n");
                    sb.append("   File: ").append(f.file())
                      .append(":").append(f.line()).append("\n");
                    sb.append("   Fix:  ").append(f.remediation()).append("\n\n");
                }
            }
        }

        return sb.toString();
    }

    public FixResult scanFixRescan(String agentCommand, BiConsumer<List<ScanResult>, Integer> onRound)
            throws ScannerException {
        Instant start = Instant.now();
        int rounds = 0;
        List<RoundResult> roundResults = new ArrayList<>();

        for (int attempt = 1; attempt <= MAX_FIX_ATTEMPTS; attempt++) {
            rounds = attempt;
            log.info("Scan-Fix-Rescan round {}/{}", attempt, MAX_FIX_ATTEMPTS);

            List<ScanResult> scanResults = scanAll();
            Verdict verdict = computeOverallVerdict(scanResults);

            if (onRound != null) {
                onRound.accept(scanResults, attempt);
            }

            RoundResult round = new RoundResult(attempt, scanResults, verdict);
            roundResults.add(round);

            if (verdict != Verdict.BLOCK) {
                log.info("Scan passed on round {}: {}", attempt, verdict);
                return new FixResult(
                    verdict,
                    roundResults,
                    Duration.between(start, Instant.now()),
                    true
                );
            }

            if (attempt < MAX_FIX_ATTEMPTS) {
                log.info("BLOCK on round {}, sending findings to agent for fix", attempt);
                try {
                    String findingsMsg = formatFindingsForAgent(scanResults);
                    AgentRunner runner = new AgentRunner(sandbox);
                    RunResult agentResult = runner.run(
                        agentCommand + " --fix-findings 2>&1",
                        300
                    );
                    log.info("Agent fix attempt {}: {}", attempt, agentResult.getStatus());
                } catch (Exception e) {
                    log.warn("Agent fix attempt {} failed: {}", attempt, e.getMessage());
                }
            }
        }

        List<ScanResult> finalResults = scanAll();
        Verdict finalVerdict = computeOverallVerdict(finalResults);

        return new FixResult(
            finalVerdict,
            roundResults,
            Duration.between(start, Instant.now()),
            false
        );
    }

    public static class RoundResult {
        private final int round;
        private final List<ScanResult> scanResults;
        private final Verdict verdict;

        public RoundResult(int round, List<ScanResult> scanResults, Verdict verdict) {
            this.round = round;
            this.scanResults = scanResults;
            this.verdict = verdict;
        }

        public int getRound() {
            return round;
        }

        public List<ScanResult> getScanResults() {
            return scanResults;
        }

        public Verdict getVerdict() {
            return verdict;
        }
    }

    public static class FixResult {
        private final Verdict finalVerdict;
        private final List<RoundResult> rounds;
        private final Duration totalDuration;
        private final boolean passed;

        public FixResult(Verdict finalVerdict, List<RoundResult> rounds,
                         Duration totalDuration, boolean passed) {
            this.finalVerdict = finalVerdict;
            this.rounds = rounds;
            this.totalDuration = totalDuration;
            this.passed = passed;
        }

        public Verdict getFinalVerdict() {
            return finalVerdict;
        }

        public List<RoundResult> getRounds() {
            return rounds;
        }

        public Duration getTotalDuration() {
            return totalDuration;
        }

        public boolean isPassed() {
            return passed;
        }

        public int totalRounds() {
            return rounds.size();
        }

        public String summary() {
            return String.format(
                "Final verdict: %s | Rounds: %d | Duration: %dms | Passed: %s",
                finalVerdict, totalRounds(), totalDuration.toMillis(), passed
            );
        }
    }
}
