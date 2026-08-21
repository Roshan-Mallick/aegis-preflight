package aegis.cli;

import aegis.audit.AuditEvent;
import aegis.audit.AuditException;
import aegis.audit.AuditLogger;
import aegis.audit.AuditStore;
import aegis.loop.RemediationLoop;
import aegis.monitor.ActivityEvent;
import aegis.preflight.Finding;
import aegis.preflight.ScanResult;
import aegis.preflight.Verdict;
import aegis.sandbox.SandboxManager;

import java.io.IOException;
import java.nio.file.*;
import java.util.List;

/**
 * Headless runner for the Aegis DEMO-CRITICAL PATH.
 *
 *   1. Start agent task in sandbox -> prove isolation (out-of-workspace and
 *      network attempts are blocked and flagged)
 *   2. Agent writes code with a planted secret, SAST bug and vulnerable
 *      dependency pin -> PreFlight (real Gitleaks + Semgrep + Trivy) catches
 *      it -> BLOCK
 *   3. Agent self-fixes from findings.json -> rescan -> PASS
 *   4. Audit log hash chain verifies -> integrity confirmed
 *   5. Local LLM (Ollama) generates the incident report — advisory only,
 *      never part of the BLOCK/PASS decision
 *   6. Competitive matrix mapping printed for the slides
 *
 * Exits 0 only if every step passes with no manual intervention.
 */
public class DemoRunner {

    private static final String TASK_CMD = "bash /workspace/agent-script.sh task";
    private static final String FIX_CMD = "bash /workspace/agent-script.sh fix";

    private final Path fixtureDir;
    private final Path runRoot;
    private final String dbPath;

    private int failures;

    public DemoRunner(Path fixtureDir, Path runRoot, String dbPath) {
        this.fixtureDir = fixtureDir;
        this.runRoot = runRoot;
        this.dbPath = dbPath;
    }

    public static void main(String[] args) throws Exception {
        Path projectRoot = Paths.get(System.getProperty("user.dir")).getParent() != null
            ? Paths.get(System.getProperty("user.dir")).getParent()
            : Paths.get(System.getProperty("user.dir"));
        Path fixtureDir = argValue(args, "--fixture",
            projectRoot.resolve("demo/fixtures/demo-project"));
        Path runRoot = argValue(args, "--run-root", projectRoot.resolve("demo/runs"));
        String db = argValue(args, "--db",
            System.getProperty("user.home") + "/.aegis/audit.db").toString();

        DemoRunner runner = new DemoRunner(fixtureDir, runRoot, db);
        int exit = runner.run();
        System.exit(exit);
    }

    private static Path argValue(String[] args, String flag, Path defaultVal) {
        return Paths.get(argValue(args, flag, defaultVal.toString()));
    }

    private static String argValue(String[] args, String flag, String defaultVal) {
        for (int i = 0; i < args.length - 1; i++) {
            if (flag.equals(args[i])) {
                return args[i + 1];
            }
        }
        return defaultVal;
    }

    public int run() throws Exception {
        banner("AEGIS PREFLIGHT — DEMO-CRITICAL PATH RUNNER");

        Files.createDirectories(runRoot);
        Path workspace = runRoot.resolve("demo-" + System.currentTimeMillis());
        copyFixture(workspace);

        try (AuditLogger audit = new AuditLogger(dbPath)) {
            System.out.println("Audit DB : " + dbPath);
            System.out.println("Workspace: " + workspace);

            // ---------- STEP 1: GATE 1 — sandbox isolation ----------
            banner("STEP 1 — GATE 1 (AEGIS): sandbox start + isolation probe");
            List<ActivityEvent> flagged;
            RemediationLoop.LoopResult result;
            try (SandboxManager sandbox = new SandboxManager(audit, ev -> { })) {
                sandbox.start(workspace);
                Thread.sleep(800); // let `docker events` attach before first exec

                RemediationLoop loop = new RemediationLoop(sandbox, audit,
                    (state, detail) -> System.out.println("  [" + state + "] " + detail));

                flagged = loop.runIsolationProbe();
                check("isolation probe produced >= 3 flagged events", flagged.size() >= 3);
                check("filesystem escape attempt flagged (R-FS-OUTSIDE)",
                    flagged.stream().anyMatch(e -> "R-FS-OUTSIDE".equals(e.rule())));
                check("network egress attempt flagged (R-NET-ANY)",
                    flagged.stream().anyMatch(e -> "R-NET-ANY".equals(e.rule())));
                for (ActivityEvent e : flagged) {
                    System.out.println("    FLAGGED: " + e.kind().label() + " — " + e.detail()
                        + " (" + e.rule() + ")");
                }

                // ---------- STEPS 2–3: GATE 2 — PreFlight remediation loop ----------
                banner("STEP 2 — GATE 2 (PREFLIGHT): agent task -> scan -> BLOCK");
                banner("STEP 3 — REMEDIATION: findings.json -> agent fix -> rescan -> PASS");

                RemediationLoop.LoopResult loopResult =
                    loop.run(TASK_CMD, FIX_CMD, 120);
                result = loopResult;

                RemediationLoop.RoundRecord firstRound = result.rounds().get(0);
                check("round 1 verdict is BLOCK", firstRound.verdict() == Verdict.BLOCK);

                boolean gitleaksSecret = firstRound.blockers().stream()
                    .anyMatch(f -> "gitleaks".equals(f.tool())
                        && f.type() == Finding.FindingType.SECRET
                        && f.file().contains("config.py"));
                check("BLOCK includes real Gitleaks SECRET finding in config.py", gitleaksSecret);

                boolean trivyVuln = firstRound.scanResults().stream()
                    .flatMap(r -> r.getFindings().stream())
                    .anyMatch(f -> "trivy".equals(f.tool()) && f.toVerdict() == Verdict.BLOCK);
                check("BLOCK includes real Trivy CVE finding", trivyVuln);

                boolean semgrepCatch = firstRound.scanResults().stream()
                    .flatMap(r -> r.getFindings().stream())
                    .anyMatch(f -> "semgrep".equals(f.tool()));
                check("Semgrep caught the planted SAST bug (bundled local rules)", semgrepCatch);

                printFindings(firstRound);

                check("final verdict is PASS/WARNING (not BLOCK)",
                    result.finalVerdict() != Verdict.BLOCK);
                check("changes RELEASED from sandbox to real filesystem", result.released());
                System.out.println("  Loop summary: rounds=" + result.rounds().size()
                    + " duration=" + result.durationMs() + "ms released=" + result.released());
            }
            System.out.println("  Sandbox torn down; released files remain on host filesystem:");
            try (DirectoryStream<Path> ds = Files.newDirectoryStream(workspace)) {
                ds.forEach(p -> System.out.println("    - " + p.getFileName()));
            }

            // ---------- STEP 4: hash-chained audit log ----------
            banner("STEP 4 — AUDIT LOG: hash chain verification");
            long rows = audit.getAuditStore().count();
            AuditStore.ChainVerification verification = audit.verifyChain();
            check("audit log has rows for this run", rows > 0);
            check("chain integrity PASS", verification.valid());
            System.out.println("  " + verification);
            assertGateDecisionsPersisted(audit);

            // ---------- STEP 5: local LLM incident report (advisory only) ----------
            banner("STEP 5 — LOCAL LLM (OLLAMA): offline incident report (ADVISORY ONLY)");
            String llmReport = aegis.ai.LocalSecurityLLM.generateReportOffline(
                lastRoundFindings(result), sandboxEvents(flagged));
            boolean llmOk = llmReport != null && !llmReport.isBlank() && !llmReport.startsWith("{");
            check("local LLM produced a human-readable incident report (localhost:11434)", llmOk);
            if (llmOk) {
                System.out.println("  --- Security Report (generated on-device by llama3.2:3b) ---");
                for (String line : llmReport.split("\n")) {
                    System.out.println("    " + line);
                }
                System.out.println("  -----------------------------------------------------------");
            }
            System.out.println("  NOTE: report is advisory only — BLOCK/PASS was decided"
                + " deterministically by scanner exit codes + policy flags.");

            // ---------- STEP 6: competitive matrix ----------
            banner("STEP 6 — COMPETITIVE MATRIX (live-demo mapping)");
            printMatrix();
        }

        banner("RESULT: " + (failures == 0 ? "ALL CHECKS PASSED" : failures + " CHECK(S) FAILED"));
        return failures == 0 ? 0 : 1;
    }

    private void assertGateDecisionsPersisted(AuditLogger audit) throws AuditException {
        List<AuditEvent> events = audit.getRecentEvents(Integer.MAX_VALUE);
        boolean block = events.stream().anyMatch(e -> e.eventType() == AuditEvent.EventType.VERDICT_BLOCK);
        boolean pass = events.stream().anyMatch(e -> e.eventType() == AuditEvent.EventType.VERDICT_PASS);
        boolean fix = events.stream().anyMatch(e -> e.eventType() == AuditEvent.EventType.FIX_APPLIED);
        boolean release = events.stream().anyMatch(e -> e.eventType() == AuditEvent.EventType.RELEASED);
        boolean sandboxStart = events.stream().anyMatch(e -> e.eventType() == AuditEvent.EventType.SANDBOX_START);
        check("gate decision row persisted: SANDBOX_START", sandboxStart);
        check("gate decision row persisted: VERDICT_BLOCK", block);
        check("gate decision row persisted: FIX_APPLIED", fix);
        check("gate decision row persisted: VERDICT_PASS", pass);
        check("gate decision row persisted: RELEASED", release);
    }

    private void printFindings(RemediationLoop.RoundRecord round) {
        System.out.println("  Findings from actual scanner output (round "
            + round.round() + ", verdict " + round.verdict() + "):");
        for (ScanResult r : round.scanResults()) {
            if (!r.isScannerAvailable()) {
                System.out.println("    [UNAVAILABLE] " + r.summary());
                continue;
            }
            System.out.println("    " + r.summary());
            for (Finding f : r.getFindings()) {
                System.out.println("      - " + f);
            }
        }
    }

    private void copyFixture(Path target) throws IOException {
        Files.createDirectories(target);
        try (var walk = Files.walk(fixtureDir)) {
            walk.forEach(src -> {
                try {
                    Path dest = target.resolve(fixtureDir.relativize(src).toString());
                    if (Files.isDirectory(src)) {
                        Files.createDirectories(dest);
                    } else {
                        Files.copy(src, dest, StandardCopyOption.REPLACE_EXISTING);
                    }
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            });
        }
        System.out.println("Fixture copied from " + fixtureDir + " -> " + target);
    }

    private List<Finding> lastRoundFindings(RemediationLoop.LoopResult result) {
        if (result == null || result.rounds().isEmpty()) {
            return List.of();
        }
        RemediationLoop.RoundRecord last = result.rounds().get(result.rounds().size() - 1);
        List<Finding> all = new java.util.ArrayList<>();
        for (ScanResult r : last.scanResults()) {
            all.addAll(r.getFindings());
        }
        return all;
    }

    private List<ActivityEvent> sandboxEvents(List<ActivityEvent> flagged) {
        return flagged == null ? List.of() : flagged;
    }

    private void printMatrix() {
        System.out.println("  Live action                          -> Differentiator");
        System.out.println("  ----------------------------------------------------------------");
        System.out.println("  Docker sandbox w/ --network=none     -> vs nono: real container isolation, not VM-per-run");
        System.out.println("  Isolation probe flagged in UI feed   -> vs Claude Sandbox: observable policy violations");
        System.out.println("  Gitleaks/Semgrep/Trivy offline BLOCK->FIX -> vs SecurePilot: deterministic scanners decide, not LLM");
        System.out.println("  Hash-chained SQLite audit + verify   -> vs Semgrep Guardian: tamper-evident local trail");
        System.out.println("  findings.json agent self-fix loop    -> unique closed-loop remediation on desktop");
        System.out.println("  Ollama llama3.2:3b incident report   -> on-device explanation, zero cloud, advisory only");
    }

    private void check(String name, boolean condition) {
        if (condition) {
            System.out.println("  [PASS] " + name);
        } else {
            failures++;
            System.out.println("  [FAIL] " + name);
        }
    }

    private void banner(String title) {
        System.out.println();
        System.out.println("==================================================================");
        System.out.println("  " + title);
        System.out.println("==================================================================");
    }
}
