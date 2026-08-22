package aegis.gui;

import aegis.audit.AuditEvent;
import aegis.session.ApprovalService;
import javafx.application.Platform;
import javafx.scene.Node;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TitledPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;
import java.util.function.Supplier;

/**
 * Active acceptance verification for the guarded-terminal feature, driven
 * through the REAL UI (real tabs, real input field, real SECURITY APPROVAL
 * REQUIRED card buttons). Enabled with -Daegis.selftest=true; results land in
 * -Daegis.selftest-out=<file> as PASS/FAIL lines ending with SELFTEST DONE.
 *
 * Covered criteria:
 *   1. ALLOW executes and streams live output (incl. >120s run: no cutoff)
 *   2. BLOCK never reaches docker exec + TOOL_BLOCKED audit row + chain intact
 *   3. REQUIRE_APPROVAL holds; Approve executes; Deny logs DEVELOPER_OVERRIDE
 *   4. 2+ tabs = 2+ independent containers; closing tabs removes containers
 *      AND their docker-events tailer processes
 *   5. PolicyEngine default policy loads from bundled resource (SessionManager
 *      construction itself proves this)
 */
final class SelfTestDriver {

    private final MainLayout layout;
    private final Path outFile;
    private final List<String> results = new ArrayList<>();
    private int failures;

    private SelfTestDriver(MainLayout layout, Path outFile) {
        this.layout = layout;
        this.outFile = outFile;
    }

    static void launch(MainLayout layout) {
        String prop = System.getProperty("aegis.selftest-out");
        Path out = (prop != null && !prop.isBlank())
            ? Paths.get(prop)
            : Paths.get(System.getProperty("user.home"), "aegis-selftest-results.txt");
        Thread t = new Thread(() -> new SelfTestDriver(layout, out).run(), "aegis-selftest");
        t.setDaemon(true);
        t.start();
    }

    private void run() {
        try {
            execute();
        } catch (Exception e) {
            record("driver-completed-without-crash", false, String.valueOf(e));
        }
        finish();
    }

    /* ------------------------------- steps ------------------------------- */

    private void execute() throws Exception {
        Thread.sleep(2500); // UI settle

        // Clean slate: stale proof files from previous runs would poison the
        // side-effect-file assertions (workspaces persist across runs).
        Path wsA = freshDir("/tmp/opencode/aegis-selftest-wsA");
        Path wsB = freshDir("/tmp/opencode/aegis-selftest-wsB");

        TerminalTab tabA = onFx(() -> layout.openAgentSession(wsA));
        TerminalTab tabB = onFx(() -> layout.openAgentSession(wsB));
        record("two-session-tabs-opened", tabA != null && tabB != null,
            "tabA=" + tabA + " tabB=" + tabB);
        if (tabA == null || tabB == null) {
            return;
        }
        String nameA = tabA.getContainerName();
        String nameB = tabB.getContainerName();

        boolean containersUp = awaitCondition(
            () -> dockerPsNames().containsAll(List.of(nameA, nameB)), 40, 500);
        record("each-tab-runs-its-own-container", containersUp,
            "expected [" + nameA + ", " + nameB + "] found " + dockerPsNames());
        int distinct = dockerPsNames().stream()
            .filter(n -> n.startsWith("aegis-sandbox-"))
            .filter(n -> n.equals(nameA) || n.equals(nameB))
            .distinct().toList().size();
        record("two-independent-containers-concurrently", containersUp && distinct == 2,
            "distinct=" + distinct);
        snapOptional(outFile.toAbsolutePath().getParent(), "selftest-1-two-tabs.png");

        // ---- AC1: ALLOW executes and streams output live ----
        // awk is on the bundled allow-list (echo is not).
        type(tabA, "awk 'BEGIN{print \"AEGIS_ALLOW_PROOF_42\"}'");
        boolean allowOk = awaitOutput(tabA,
            List.of("AEGIS_ALLOW_PROOF_42", "[exit 0]"), 60);
        record("ALLOW-executes-and-streams-output", allowOk,
            "output-tail=" + tailOf(tabA));
        record("audit-COMMAND_ALLOWED-row",
            auditHas(AuditEvent.EventType.COMMAND_ALLOWED, "awk"),
            "");

        // ---- AC2: BLOCK never reaches docker exec ----
        String blockedTarget = "/workspace/blocked-should-not-exist.txt";
        type(tabA, "curl http://example.com > " + blockedTarget + " 2>&1");
        boolean blockedShown = awaitOutput(tabA, List.of("[AEGIS GATE] BLOCKED"), 20);
        Thread.sleep(1500); // grace period in case a buggy gate had executed it
        boolean fileAbsent = !Files.exists(wsA.resolve("blocked-should-not-exist.txt"));
        boolean auditRow = auditHas(AuditEvent.EventType.TOOL_BLOCKED, "curl");
        record("BLOCK-shown-in-terminal", blockedShown, "output-tail=" + tailOf(tabA));
        record("BLOCK-never-reached-docker-exec", blockedShown && fileAbsent,
            "side-effect-file-absent=" + fileAbsent);
        record("BLOCK-audited-as-TOOL_BLOCKED", auditRow, "");

        // ---- AC3a: REQUIRE_APPROVAL holds, card lists it, Approve executes ----
        // While held, execution can only be evidenced by signals that CANNOT
        // come from the typed-command echo: a new "[exit" completion line,
        // the "Approved — executing" notice, or the side-effect file.
        String heldCmd = "bash -c 'echo APPROVED_EXEC_PROOF > "
            + "/workspace/approved-proof.txt'";
        Files.deleteIfExists(wsA.resolve("approved-proof.txt"));
        type(tabA, heldCmd);
        boolean heldVisible = awaitCondition(
            () -> onFx(layout.getApprovalCardForTest()::isVisible)
                && !layout.getSessionManager().getApprovalService().snapshot().isEmpty(),
            20, 400);
        record("REQUIRE_APPROVAL-holds-command-and-card-appears", heldVisible,
            "pending=" + layout.getSessionManager().getApprovalService().snapshot());
        int exitsBeforeHold = countOccurrences(outputOf(tabA), "[exit ");
        Thread.sleep(2000); // while still held: must NOT have executed yet
        boolean notExecutedWhileHeld =
            !Files.exists(wsA.resolve("approved-proof.txt"))
                && !awaitOutputContains(tabA, "Approved — executing held command")
                && countOccurrences(outputOf(tabA), "[exit ") == exitsBeforeHold;
        record("held-command-genuinely-waits-without-executing", notExecutedWhileHeld,
            "proof-file-absent=" + !Files.exists(wsA.resolve("approved-proof.txt"))
                + " approved-notice-absent="
                + !awaitOutputContains(tabA, "Approved — executing held command")
                + " no-new-exit-lines="
                + (countOccurrences(outputOf(tabA), "[exit ") == exitsBeforeHold));
        Button approveBtn = findCardButton(heldCmd.substring(0, 34), "Approve");
        record("card-has-real-Approve-button", approveBtn != null, "");
        if (approveBtn != null) {
            onFx(approveBtn::fire);
            boolean executedAfterApprove = awaitCondition(() ->
                    awaitOutputContains(tabA, "Approved — executing held command")
                        && Files.exists(wsA.resolve("approved-proof.txt"))
                        && countOccurrences(outputOf(tabA), "[exit ")
                            == exitsBeforeHold + 1,
                40, 400);
            record("Approve-executes-held-command", executedAfterApprove,
                "output-tail=" + tailOf(tabA));
            record("audit-APPROVAL_GRANTED-row",
                auditHas(AuditEvent.EventType.APPROVAL_GRANTED, "GRANTED"), "");
        }
        snapOptional(outFile.toAbsolutePath().getParent(), "selftest-2-approval-card.png");

        // ---- AC3b: Deny prevents execution ----
        Files.deleteIfExists(wsB.resolve("denied-should-not-exist.txt"));
        type(tabB, "uname -a > /workspace/denied-should-not-exist.txt");
        boolean denyHeld = awaitCondition(
            () -> !layout.getSessionManager().getApprovalService().snapshot().isEmpty(),
            20, 400);
        Button denyBtn = denyHeld
            ? findCardButton("uname -a > /workspace/denied", "Deny") : null;
        record("card-has-real-Deny-button", denyBtn != null, "");
        if (denyBtn != null) {
            onFx(denyBtn::fire);
            boolean deniedShown = awaitOutput(tabB, List.of("Approval DENIED"), 20);
            Thread.sleep(2000);
            boolean neverRan = !Files.exists(wsB.resolve("denied-should-not-exist.txt"));
            boolean unameNeverAppeared = !awaitOutputContains(tabB, "Linux");
            record("Deny-prevents-execution", deniedShown && neverRan && unameNeverAppeared,
                "deniedShown=" + deniedShown + " fileAbsent=" + neverRan);
            record("audit-DEVELOPER_OVERRIDE-row-for-denial",
                auditHas(AuditEvent.EventType.DEVELOPER_OVERRIDE, "DENIED"), "");
        }

        // ---- AC1b: no artificial 120s cutoff for long-running output ----
        // awk is allow-listed (a raw `for` shell loop would be rightly held).
        long longStart = System.currentTimeMillis();
        type(tabB, "awk 'BEGIN{for(i=1;i<=13;i++){printf \"TICK_%d\\n\",i;"
            + "fflush();system(\"sleep 10\")}}'");
        boolean[] ticks = new boolean[14];
        boolean longOk = awaitCondition(() -> {
            String text = outputOf(tabB);
            for (int i = 1; i <= 13; i++) {
                if (!ticks[i] && text.contains("TICK_" + i)) {
                    ticks[i] = true;
                }
            }
            return ticks[13] && text.contains("[exit 0]");
        }, 230, 1000);
        long durSec = (System.currentTimeMillis() - longStart) / 1000;
        int tickCount = 0;
        for (int i = 1; i <= 13; i++) {
            if (ticks[i]) {
                tickCount++;
            }
        }
        record("long-running-command-streams-past-120s-no-cutoff",
            longOk && durSec >= 115 && tickCount == 13,
            "durationSeconds=" + durSec + " ticksSeen=" + tickCount + "/13");

        // ---- AC4: closing tabs cleans up containers AND tailers ----
        int tailersBeforeClose = countDockerEventsTailers(nameA, nameB);
        int tabsBefore = onFx(() -> layout.getCenterTabsForTest().getTabs().size());
        Boolean removedA = onFx(() ->
            layout.getCenterTabsForTest().getTabs().remove((javafx.scene.control.Tab) tabA));
        Boolean removedB = onFx(() ->
            layout.getCenterTabsForTest().getTabs().remove((javafx.scene.control.Tab) tabB));
        int tabsAfter = onFx(() -> layout.getCenterTabsForTest().getTabs().size());
        boolean allClean = awaitCondition(() ->
                dockerPsNames().stream().noneMatch(n -> n.startsWith("aegis-sandbox-"))
                    && countDockerEventsTailers(nameA, nameB) == 0
                    && layout.getSessionManager().activeSessionCount() == 0,
            45, 500);
        record("closing-tabs-removed-containers", allClean,
            "tabsBefore=" + tabsBefore + " removedA=" + removedA
                + " removedB=" + removedB + " tabsAfter=" + tabsAfter
                + " containersAfter=" + dockerPsNames()
                + " tailersBefore=" + tailersBeforeClose
                + " tailersAfter=" + countDockerEventsTailers(nameA, nameB));

        // ---- AC5/AC6 support: hash chain still verifies after decisions ----
        boolean chainOk = false;
        String chainMsg = "no audit";
        if (layout.getSessionAudit() != null) {
            var v = layout.getSessionAudit().verifyChain();
            chainOk = v.valid();
            chainMsg = v.toString();
        }
        record("audit-hash-chain-verifies-after-all-decisions", chainOk, chainMsg);

        snapOptional(outFile.toAbsolutePath().getParent(), "selftest-3-after-cleanup.png");
    }

    /* ------------------------------ helpers ------------------------------ */

    /** Deletes then recreates a directory so runs never see stale artifacts. */
    private static Path freshDir(String path) throws IOException {
        Path p = Paths.get(path);
        if (Files.exists(p)) {
            try (var walk = Files.walk(p)) {
                walk.sorted(java.util.Comparator.reverseOrder()).forEach(f -> {
                    try {
                        Files.delete(f);
                    } catch (IOException ignored) {
                    }
                });
            }
        }
        return Files.createDirectories(p);
    }

    private static int countOccurrences(String haystack, String needle) {
        int count = 0;
        int idx = 0;
        while ((idx = haystack.indexOf(needle, idx)) >= 0) {
            count++;
            idx += needle.length();
        }
        return count;
    }

    /** Screenshot best-effort: skipped (never fatal) while window is hidden. */
    private void snapOptional(Path parent, String name) {
        try {
            layout.saveSceneSnapshot(parent.resolve(name));
        } catch (Exception e) {
            results.add("WARN screenshot " + name + " skipped: " + e.getMessage());
        }
    }

    private <T> T onFx(Supplier<T> supplier) {
        FutureTask<T> task = new FutureTask<>(supplier::get);
        Platform.runLater(task);
        try {
            return task.get(30, TimeUnit.SECONDS);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private void onFx(Runnable action) {
        onFx(() -> {
            action.run();
            return null;
        });
    }

    private void type(TerminalTab tab, String command) {
        onFx(() -> {
            tab.inputFieldForTest().setText(command);
            tab.submit();
        });
    }

    private String outputOf(TerminalTab tab) {
        return onFx(tab::outputTextForTest);
    }

    private boolean awaitOutput(TerminalTab tab, List<String> allOf, int timeoutSec) {
        return awaitCondition(() -> {
            String text = outputOf(tab);
            return allOf.stream().allMatch(text::contains);
        }, timeoutSec, 400);
    }

    private boolean awaitOutputContains(TerminalTab tab, String needle) {
        return outputOf(tab).contains(needle);
    }

    private String tailOf(TerminalTab tab) {
        String text = outputOf(tab);
        String[] lines = text.split("\n");
        int from = Math.max(0, lines.length - 4);
        return String.join(" | ", Arrays.asList(lines).subList(from, lines.length))
            .replace("\n", " ");
    }

    private boolean awaitCondition(BooleanSupplier condition, int timeoutSec, long pollMs) {
        long deadline = System.currentTimeMillis() + timeoutSec * 1000L;
        while (System.currentTimeMillis() < deadline) {
            try {
                if (condition.getAsBoolean()) {
                    return true;
                }
            } catch (Exception ignored) {
            }
            try {
                Thread.sleep(pollMs);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
        }
        return condition.getAsBoolean();
    }

    private List<String> dockerPsNames() {
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
            results.add("WARN docker ps failed: " + e.getMessage());
            return List.of();
        }
    }

    /**
     * Counts OUR per-session `docker events` tailer processes via /proc,
     * scoped to the given container names so orphaned tailers from previous
     * crashed runs cannot pollute the measurement.
     */
    private int countDockerEventsTailers(String... containerNames) {
        File procDir = new File("/proc");
        File[] pidDirs = procDir.listFiles(File::isDirectory);
        if (pidDirs == null) {
            return -1;
        }
        List<String> markers = Arrays.stream(containerNames)
            .map(n -> "container=" + n)
            .toList();
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
                    && markers.stream().anyMatch(s::contains)) {
                    count++;
                }
            } catch (IOException ignored) {
            }
        }
        return count;
    }

    private boolean auditHas(AuditEvent.EventType type, String payloadContains) {
        try {
            if (layout.getSessionAudit() == null) {
                return false;
            }
            for (AuditEvent e : layout.getSessionAudit().getRecentEvents(Integer.MAX_VALUE)) {
                if (e.eventType() == type
                    && e.payloadJson().contains(payloadContains)) {
                    return true;
                }
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    /** Finds an Approve/Deny button of the card row holding cmdSubstring. */
    private Button findCardButton(String cmdSubstring, String buttonText) {
        return onFx(() -> {
            TitledPane card = layout.getApprovalCardForTest();
            if (!(card.getContent() instanceof VBox rows)) {
                return null;
            }
            for (Node rowNode : rows.getChildren()) {
                if (!(rowNode instanceof VBox row) || row.getChildren().size() < 3) {
                    continue;
                }
                Node first = row.getChildren().get(0);
                if (!(first instanceof Label cmdLabel)
                    || !cmdLabel.getText().contains(cmdSubstring)) {
                    continue;
                }
                Node btnsNode = row.getChildren().get(2);
                if (btnsNode instanceof HBox hbox) {
                    for (Node n : hbox.getChildren()) {
                        if (n instanceof Button b && b.getText().equals(buttonText)) {
                            return b;
                        }
                    }
                }
            }
            return null;
        });
    }

    private void record(String criterion, boolean passed, String detail) {
        String line = (passed ? "PASS " : "FAIL ") + criterion
            + (detail == null || detail.isBlank() ? "" : "   [" + detail + "]");
        results.add(line);
        System.out.println("[selftest] " + line);
        if (!passed) {
            failures++;
        }
        flushResults(); // incremental: survive external app termination
    }

    private void flushResults() {
        try {
            List<String> snapshot = new ArrayList<>(results);
            Files.write(outFile, (String.join("\n", snapshot) + "\n")
                .getBytes(StandardCharsets.UTF_8));
        } catch (IOException ignored) {
        }
    }

    private void finish() {
        results.add(failures == 0
            ? "RESULT: ALL CHECKS PASSED"
            : "RESULT: " + failures + " CHECK(S) FAILED");
        results.add("SELFTEST DONE");
        flushResults();
        System.out.println("[selftest] results written to "
            + outFile.toAbsolutePath());
    }
}
