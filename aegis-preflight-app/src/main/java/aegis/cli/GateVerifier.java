package aegis.cli;

import aegis.audit.AuditEvent;
import aegis.audit.AuditException;
import aegis.audit.AuditLogger;
import aegis.session.ApprovalService;
import aegis.session.SessionManager;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;
import java.util.function.Supplier;

/**
 * Headless acceptance verifier for the guarded-terminal gate pipeline,
 * running against a REAL Docker daemon.
 *
 *   java -cp aegis-preflight-*-all.jar aegis.cli.GateVerifier [--quick]
 *
 * Verifies:
 *   1. ALLOW commands execute and stream live output (COMMAND_ALLOWED row)
 *   2. BLOCK commands NEVER reach docker exec (side-effect-file proof +
 *      TOOL_BLOCKED audit row)
 *   3. REQUIRE_APPROVAL commands genuinely wait without executing; Approve
 *      releases them via execStreaming; Deny permanently prevents execution
 *      (DEVELOPER_OVERRIDE row)
 *   4. N concurrent sessions = N independent containers, all torn down
 *      together with their docker-events tailers when closed
 *   5. Streaming has NO fixed wall-clock cutoff (long test runs past the old
 *      120s cap; skipped with --quick)
 *   6. The hash-chained audit log still verifies after every decision
 */
public class GateVerifier {

    private int failures;

    /** Sink that records everything a session's terminal would display. */
    static final class RecordingSink implements SessionManager.StreamSink {
        final List<String> lines = new ArrayList<>();
        final Object lock = new Object();
        volatile Integer lastExit;
        volatile String blockReason;
        volatile String pendingId;
        volatile boolean deniedNotice;
        final CountDownLatch completed = new CountDownLatch(1);
        final CountDownLatch blockedLatch = new CountDownLatch(1);
        final CountDownLatch pendingLatch = new CountDownLatch(1);

        @Override
        public void onLine(String line) {
            synchronized (lock) {
                lines.add(line);
                if (line.contains("Approval DENIED")) {
                    deniedNotice = true;
                }
            }
        }

        @Override
        public void onCompleted(int exitCode) {
            lastExit = exitCode;
            completed.countDown();
        }

        @Override
        public void onBlocked(String reason) {
            blockReason = reason;
            blockedLatch.countDown();
        }

        @Override
        public void onPending(String approvalId, String reason) {
            pendingId = approvalId;
            pendingLatch.countDown();
        }

        boolean saw(String needle) {
            synchronized (lock) {
                return lines.stream().anyMatch(l -> l.contains(needle));
            }
        }

        void resetForNextCommand() {
            synchronized (lock) {
                lines.clear();
                lastExit = null;
                blockReason = null;
                pendingId = null;
                deniedNotice = false;
            }
            // fresh latches by reflection-free reassignment is impossible
            // (final fields), so tests use waitFor(...) with predicates over
            // flags instead of raw latches after the first command.
        }
    }

    public static void main(String[] args) throws Exception {
        boolean quick = List.of(args).contains("--quick");
        int exit = new GateVerifier().run(quick);
        System.exit(exit);
    }

    private int run(boolean quick) throws Exception {
        banner("AEGIS GATE VERIFIER — guarded terminal end-to-end");

        Path ws = Files.createTempDirectory("aegis-gateverify-ws");
        Path db = Files.createTempDirectory("aegis-gateverify-db").resolve("audit.db");
        System.out.println("Workspace: " + ws);
        System.out.println("Audit DB : " + db);

        try (AuditLogger audit = new AuditLogger(db.toString())) {
            SessionManager sessions = new SessionManager(audit, null, l -> { });
            try {
                RecordingSink sink = new RecordingSink();

                // ---------- Session 1 ----------
                long t0 = System.currentTimeMillis();
                String s1 = sessions.createSession(ws, ev -> { }, sink);
                System.out.println("Session S1: " + s1 + " -> "
                    + sessions.getSession(s1).getContainerName()
                    + " (" + (System.currentTimeMillis() - t0) + "ms)");
                check("session-1-container-started",
                    sessions.activeSessionCount() == 1);

                // ---- 1. ALLOW ----
                // NOTE: the command must use an ALLOW-LISTED tool from the
                // bundled policy (awk is on the list; echo is not!).
                sink.resetForNextCommand();
                sessions.submitCommand(s1,
                    "awk 'BEGIN{print \"GATE_ALLOW_PROOF_42\"}'");
                boolean allowDone = await(() ->
                    sink.lastExit != null && sink.saw("GATE_ALLOW_PROOF_42"), 30);
                check("ALLOW-executes-and-streams-output", allowDone,
                    "exit=" + sink.lastExit);
                check("ALLOW-exit-code-zero",
                    allowDone && sink.lastExit != null && sink.lastExit == 0, "");
                check("audit-row-COMMAND_ALLOWED",
                    auditHas(audit, AuditEvent.EventType.COMMAND_ALLOWED, "awk"), "");

                // ---- 2. BLOCK (never reaches docker exec) ----
                sink.resetForNextCommand();
                Path blockedFile = ws.resolve("blocked-should-not-exist.txt");
                sessions.submitCommand(s1,
                    "curl http://example.com > " + blockedFile + " 2>&1");
                boolean blockFast = await(() -> sink.blockedLatch.getCount() == 0, 10);
                Thread.sleep(1500); // grace in case a buggy gate had executed it
                check("BLOCK-decision-shown-immediately", blockFast,
                    "reason=" + sink.blockReason);
                check("BLOCK-never-reached-docker-exec",
                    !Files.exists(blockedFile),
                    "side-effect file absent=" + !Files.exists(blockedFile));
                check("audit-row-TOOL_BLOCKED",
                    auditHas(audit, AuditEvent.EventType.TOOL_BLOCKED, "curl"), "");

                // ---- 3. REQUIRE_APPROVAL: holds, then Approve executes ----
                drainPending(sessions);
                sink.resetForNextCommand();
                sessions.submitCommand(s1, "bash -c 'echo APPROVED_EXEC_PROOF'");
                boolean held = await(() -> sink.pendingLatch.getCount() == 0, 15);
                ApprovalService approvals = sessions.getApprovalService();
                Thread.sleep(1500); // while held: must NOT have executed
                boolean waitedWithoutExecuting =
                    held && sink.pendingId != null && sink.lastExit == null
                        && !sink.saw("APPROVED_EXEC_PROOF")
                        && approvals.snapshot().size() == 1;
                check("REQUIRE_APPROVAL-genuinely-waits-without-executing",
                    waitedWithoutExecuting,
                    "pendingId=" + sink.pendingId);
                check("audit-row-APPROVAL_REQUESTED",
                    auditHas(audit, AuditEvent.EventType.APPROVAL_REQUESTED,
                        "bash -c 'echo APPROVED_EXEC_PROOF'"), "");

                String approveId = sink.pendingId;
                if (approveId != null) {
                    boolean approvedInQueue = approvals.approve(approveId, "verifier");
                    boolean approvedExecuted = await(() ->
                        sink.lastExit != null && sink.saw("APPROVED_EXEC_PROOF"), 40);
                    check("Approve-releases-held-command-via-execStreaming",
                        approvedInQueue && approvedExecuted, "exit=" + sink.lastExit);
                    check("audit-row-APPROVAL_GRANTED",
                        auditHas(audit, AuditEvent.EventType.APPROVAL_GRANTED,
                            "APPROVED_EXEC_PROOF"), "");
                } else {
                    check("Approve-releases-held-command-via-execStreaming",
                        false, "no approval id");
                }

                // ---- 4. Deny prevents execution ----
                drainPending(sessions);
                sink.resetForNextCommand();
                sessions.submitCommand(s1, "uname -a");
                boolean held2 = await(() -> sink.pendingLatch.getCount() == 0, 15);
                String denyId = held2 ? sink.pendingId : null;
                if (denyId != null) {
                    boolean denied = sessions.getApprovalService()
                        .deny(denyId, "verifier", "gate-verifier deny test");
                    Thread.sleep(2000);
                    boolean neverRan = !sink.saw("Linux") && sink.lastExit == null;
                    check("Deny-prevents-execution-permanently",
                        denied && sink.deniedNotice && neverRan,
                        "deniedNotice=" + sink.deniedNotice + " neverRan=" + neverRan);
                    check("audit-row-DEVELOPER_OVERRIDE-for-denial",
                        auditHas(audit, AuditEvent.EventType.DEVELOPER_OVERRIDE,
                            "DENIED"), "");
                } else {
                    check("Deny-prevents-execution-permanently", false, "no id");
                }

                // ---- 5. Multiple independent containers ----
                RecordingSink sinkB = new RecordingSink();
                RecordingSink sinkC = new RecordingSink();
                String s2 = sessions.createSession(ws, ev -> { }, sinkB);
                String s3 = sessions.createSession(ws, ev -> { }, sinkC);
                List<String> names = dockerPsNames();
                boolean threeUp = sessions.activeSessionCount() == 3
                    && names.contains(sessions.getSession(s2).getContainerName())
                    && names.contains(sessions.getSession(s3).getContainerName());
                check("three-concurrent-independent-containers", threeUp,
                    "docker-ps=" + names);

                // ---- 6. Long-running streaming (no fixed cutoff) ----
                boolean streamedAll = false;
                int ticksSeen = 0;
                long longElapsedSec = -1;
                if (!quick) {
                    // awk is allow-listed (a raw `for ...` shell loop is NOT —
                    // the gate would rightly hold it). Emits 13 ticks x 10s
                    // ~= 130s total, deliberately past the old fixed 120s cap.
                    // fflush() forces per-tick line streaming through the pipe.
                    sinkB.resetForNextCommand();
                    sessions.submitCommand(s2,
                        "awk 'BEGIN{for(i=1;i<=13;i++){printf \"TICK_%d\\n\",i;"
                            + "fflush();system(\"sleep 10\")}}'");
                    boolean[] seen = new boolean[14];
                    long longStart = System.currentTimeMillis();
                    streamedAll = await(() -> {
                        for (int i = 1; i <= 13; i++) {
                            if (!seen[i] && sinkB.saw("TICK_" + i)) {
                                seen[i] = true;
                            }
                        }
                        return seen[13] && sinkB.lastExit != null;
                    }, 230);
                    longElapsedSec = (System.currentTimeMillis() - longStart) / 1000;
                    for (int i = 1; i <= 13; i++) {
                        if (seen[i]) {
                            ticksSeen++;
                        }
                    }
                }
                check("streaming-has-no-fixed-120s-cutoff",
                    quick || (streamedAll && ticksSeen == 13 && sinkB.lastExit != null),
                    quick ? "(--quick skipped)"
                        : "ticksSeen=" + ticksSeen + "/13 exitCode=" + sinkB.lastExit
                            + " elapsedSec=" + longElapsedSec);

                // ---- 7. Teardown: containers AND tailer processes ----
                int tailersBeforeClose = countDockerEventsTailers();
                sessions.close();
                boolean clean = await(() ->
                    dockerPsNames().stream()
                        .noneMatch(n -> n.startsWith("aegis-sandbox-"))
                    && countDockerEventsTailers() == 0
                    && sessions.activeSessionCount() == 0, 45);
                check("closing-all-sessions-removed-containers-and-tailers",
                    clean, "tailersBefore=" + tailersBeforeClose
                        + " tailersAfter=" + countDockerEventsTailers());

                // ---- 8. Chain integrity after every decision type ----
                var verification = audit.verifyChain();
                check("hash-chain-verifies-after-all-command-decisions",
                    verification.valid(), verification.toString());
            } finally {
                sessions.close();
            }
        }

        banner("RESULT: " + (failures == 0 ? "ALL CHECKS PASSED"
            : failures + " CHECK(S) FAILED"));
        return failures == 0 ? 0 : 1;
    }

    /* ------------------------------ helpers ------------------------------ */

    /** Resolves any leftover held commands so steps start from an empty queue. */
    private static void drainPending(SessionManager sessions) {
        ApprovalService approvals = sessions.getApprovalService();
        for (ApprovalService.PendingRequest r : approvals.snapshot()) {
            approvals.deny(r.id(), "verifier", "drain before next step");
        }
    }

    private static boolean await(BooleanSupplier condition, int timeoutSec) {
        long deadline = System.currentTimeMillis() + timeoutSec * 1000L;
        while (System.currentTimeMillis() < deadline) {
            try {
                if (condition.getAsBoolean()) {
                    return true;
                }
            } catch (Exception ignored) {
            }
            try {
                Thread.sleep(200);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
        }
        return condition.getAsBoolean();
    }

    private static boolean auditHas(AuditLogger audit, AuditEvent.EventType type,
                                    String payloadContains) {
        try {
            return audit.getRecentEvents(Integer.MAX_VALUE).stream()
                .anyMatch(e -> e.eventType() == type
                    && e.payloadJson().contains(payloadContains));
        } catch (AuditException e) {
            return false;
        }
    }

    private static List<String> dockerPsNames() {
        try {
            Process p = new ProcessBuilder(
                "docker", "ps", "--format", "{{.Names}}").start();
            List<String> names = new ArrayList<>();
            try (var reader = new java.io.BufferedReader(
                    new java.io.InputStreamReader(p.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (!line.isBlank()) {
                        names.add(line.strip());
                    }
                }
            }
            p.waitFor(15, TimeUnit.SECONDS);
            return names;
        } catch (Exception e) {
            System.err.println("[GateVerifier] docker ps failed: " + e.getMessage());
            return List.of();
        }
    }

    /** Counts our per-session `docker events` tailer processes via /proc. */
    private static int countDockerEventsTailers() {
        File procDir = new File("/proc");
        File[] pidDirs = procDir.listFiles(File::isDirectory);
        if (pidDirs == null) {
            return -1;
        }
        int count = 0;
        for (File dir : pidDirs) {
            if (!dir.getName().chars().allMatch(Character::isDigit)) {
                continue;
            }
            Path cmdline = dir.toPath().resolve("cmdline");
            try {
                if (!Files.exists(cmdline)) {
                    continue;
                }
                String s = new String(Files.readAllBytes(cmdline), StandardCharsets.UTF_8)
                    .replace('\0', ' ');
                if (s.contains("docker") && s.contains("events")
                    && s.contains("container=aegis-sandbox-")) {
                    count++;
                }
            } catch (IOException ignored) {
            }
        }
        return count;
    }

    private void check(String name, boolean condition) {
        check(name, condition, "");
    }

    private void check(String name, boolean condition, String detail) {
        String line = (condition ? "[PASS] " : "[FAIL] ") + name
            + (detail == null || detail.isBlank() ? "" : "   [" + detail + "]");
        System.out.println("  " + line);
        if (!condition) {
            failures++;
        }
    }

    private static void banner(String title) {
        System.out.println();
        System.out.println("==================================================================");
        System.out.println("  " + title);
        System.out.println("==================================================================");
    }
}
