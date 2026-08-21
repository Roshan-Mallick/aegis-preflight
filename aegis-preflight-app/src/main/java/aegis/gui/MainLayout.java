package aegis.gui;

import aegis.preflight.Finding;
import aegis.preflight.Verdict;
import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.scene.paint.Color;
import javafx.scene.text.Font;
import javafx.scene.text.FontWeight;
import javafx.stage.DirectoryChooser;
import javafx.stage.Window;

import java.io.IOException;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Stream;

public class MainLayout extends BorderPane {

    private static final int MAX_LOG_LINES = 500;
    private static final String VERSION = "v0.1.0";

    private final TextField workspacePath;
    private final TextArea logOutput;
    private final TextArea securityReport;
    private final TitledPane securityReportPane;
    private final VBox findingsPanel;
    private final Label verdictLabel;
    private final Button scanButton;
    private final ProgressBar progressBar;
    private final Label findingsCountLabel;
    private final Label blockersCountLabel;
    private final CheckBox secretsCheck;
    private final CheckBox depsCheck;
    private final CheckBox configCheck;

    private List<Finding> lastFindings = new ArrayList<>();

    private static final Set<String> SENSITIVE_EXTENSIONS = Set.of(
        ".pem", ".key", ".p12", ".pfx", ".jks", ".keystore"
    );

    public MainLayout() {
        setPadding(new Insets(0));

        workspacePath = new TextField(System.getProperty("aegis.workspace",
            System.getProperty("user.home")));
        workspacePath.setPrefWidth(180);
        workspacePath.setPromptText("Project directory");
        workspacePath.getStyleClass().add("workspace-field");
        workspacePath.setOnAction(e -> runScan());

        Button browseBtn = new Button("Browse...");
        browseBtn.getStyleClass().add("browse-btn");
        browseBtn.setOnAction(e -> openDirectoryChooser());

        HBox workspaceRow = new HBox(6, workspacePath, browseBtn);
        HBox.setHgrow(workspacePath, Priority.ALWAYS);
        workspaceRow.setAlignment(Pos.CENTER_LEFT);

        scanButton = new Button("Run PreFlight Scan");
        scanButton.getStyleClass().add("scan-button");
        scanButton.setMaxWidth(Double.MAX_VALUE);
        scanButton.setOnAction(e -> runScan());

        progressBar = new ProgressBar(0);
        progressBar.setVisible(false);
        progressBar.setMaxWidth(Double.MAX_VALUE);

        secretsCheck = new CheckBox("Secret Detection (Gitleaks)");
        secretsCheck.setSelected(true);
        secretsCheck.setTextFill(Color.LIGHTGRAY);

        depsCheck = new CheckBox("Dependency Audit");
        depsCheck.setSelected(true);
        depsCheck.setTextFill(Color.LIGHTGRAY);

        configCheck = new CheckBox("Config Analysis");
        configCheck.setSelected(true);
        configCheck.setTextFill(Color.LIGHTGRAY);

        verdictLabel = new Label("No scan yet");
        verdictLabel.setFont(Font.font("System", FontWeight.BOLD, 22));
        verdictLabel.setTextFill(Color.LIGHTGRAY);
        verdictLabel.setWrapText(true);

        findingsCountLabel = new Label("Findings: 0");
        findingsCountLabel.setTextFill(Color.LIGHTGRAY);

        blockersCountLabel = new Label("Blockers: 0");
        blockersCountLabel.setTextFill(Color.LIGHTGRAY);

        HBox stats = new HBox(15, findingsCountLabel, blockersCountLabel);
        stats.setAlignment(Pos.CENTER_LEFT);

        Label version = new Label(VERSION);
        version.setFont(Font.font("System", 10));
        version.setTextFill(Color.GRAY);

        Button aboutBtn = new Button("About / Offline Status");
        aboutBtn.setMaxWidth(Double.MAX_VALUE);
        aboutBtn.getStyleClass().add("browse-btn");
        aboutBtn.setOnAction(e -> showAboutDialog());

        Region spacer = new Region();
        VBox.setVgrow(spacer, Priority.ALWAYS);

        VBox sidebar = new VBox(10,
            buildTitle(),
            new Separator(),
            label("Workspace Directory", true), workspaceRow,
            spacer,
            label("Scan Controls", true), scanButton, progressBar,
            secretsCheck, depsCheck, configCheck,
            new Separator(),
            label("Last Verdict", true), verdictLabel, stats,
            aboutBtn,
            new Region(), version
        );
        sidebar.setPrefWidth(290);
        sidebar.setMinWidth(290);
        sidebar.setPadding(new Insets(15));
        sidebar.getStyleClass().add("sidebar");
        setLeft(sidebar);

        logOutput = new TextArea();
        logOutput.setEditable(false);
        logOutput.setWrapText(true);
        logOutput.setFont(Font.font("Monospaced", 12));
        logOutput.getStyleClass().add("log-output");
        VBox.setVgrow(logOutput, Priority.ALWAYS);

        findingsPanel = new VBox(4);
        findingsPanel.setPadding(new Insets(8));
        ScrollPane findingsScroll = new ScrollPane(findingsPanel);
        findingsScroll.setFitToWidth(true);
        findingsScroll.setPrefHeight(220);
        findingsScroll.getStyleClass().add("findings-scroll");
        TitledPane findingsPane = new TitledPane("Detailed Findings", findingsScroll);
        findingsPane.setCollapsible(true);
        findingsPane.setExpanded(true);
        findingsPane.getStyleClass().add("findings-pane");

        securityReport = new TextArea();
        securityReport.setEditable(false);
        securityReport.setWrapText(true);
        securityReport.setFont(Font.font("System", 12));
        securityReport.setPrefHeight(110);
        securityReport.setText("Run a scan — the on-device model (" + aegis.ai.LocalSecurityLLM.MODEL
            + ") will explain the results here. Advisory only; never decides BLOCK/PASS.");
        securityReportPane = new TitledPane("Security Report (on-device LLM — advisory only)", securityReport);

        Label header = new Label("Scan Results");
        header.setFont(Font.font("System", FontWeight.BOLD, 16));

        VBox center = new VBox(8, header, logOutput, findingsPane, securityReportPane);
        center.setPadding(new Insets(15));
        setCenter(center);

        if (Boolean.getBoolean("aegis.autoscan")) {
            Thread t = new Thread(() -> {
                try {
                    Thread.sleep(1500);
                } catch (InterruptedException ignored) {
                }
                Platform.runLater(this::runScan);
            }, "autoscan-trigger");
            t.setDaemon(true);
            t.start();
        }
    }

    /**
     * Test/demo instrumentation: dumps the final Security Report card text to
     * the file given via -Daegis.report-out=&lt;file&gt; so the exact displayed
     * content can be verified without screen capture.
     */
    private void dumpReportIfRequested(String text) {
        String path = System.getProperty("aegis.report-out");
        if (path == null || path.isBlank()) {
            return;
        }
        try {
            Files.writeString(Paths.get(path), text);
        } catch (IOException e) {
            appendLog("[security-report] dump failed: " + e.getMessage());
        }
    }

    /**
     * Test/demo instrumentation: writes a snapshot of the whole scene to the
     * path given via -Daegis.screenshot=&lt;file.png&gt; (no external tools).
     */
    private void captureScreenshotIfRequested() {
        String path = System.getProperty("aegis.screenshot");
        if (path == null || path.isBlank() || getScene() == null) {
            return;
        }
        try {
            javafx.scene.image.WritableImage img = getScene().snapshot(null);
            int w = (int) img.getWidth();
            int h = (int) img.getHeight();
            java.awt.image.BufferedImage bi =
                new java.awt.image.BufferedImage(w, h, java.awt.image.BufferedImage.TYPE_INT_ARGB);
            int[] buffer = new int[w * h];
            img.getPixelReader().getPixels(0, 0, w, h,
                javafx.scene.image.PixelFormat.getIntArgbInstance(), buffer, 0, w);
            bi.setRGB(0, 0, w, h, buffer, 0, w);
            javax.imageio.ImageIO.write(bi, "png", new java.io.File(path));
            appendLog("[screenshot] saved scene snapshot to " + path);
        } catch (Exception e) {
            appendLog("[screenshot] failed: " + e.getMessage());
        }
    }

    /**
     * About dialog with the honest offline claim — "fully offline" is only
     * true after the documented one-time setup (Semgrep rules, Trivy DB,
     * Ollama model are pre-downloaded during installation).
     */
    private void showAboutDialog() {
        Alert about = new Alert(Alert.AlertType.INFORMATION);
        about.setTitle("About Aegis PreFlight");
        about.setHeaderText("Aegis PreFlight " + VERSION + " — Security for AI Coding");
        about.setContentText(
            "Fully offline after one-time setup (Semgrep rules, Trivy vulnerability DB, "
            + "Ollama model — all pre-downloaded during installation). "
            + "No runtime internet connection required.\n\n"
            + "- Gate 1: Docker sandbox with --network=none, read-only rootfs\n"
            + "- Gate 2: Gitleaks + Semgrep (bundled rules) + Trivy (cached DB), all local\n"
            + "- Block-Fix-Rescan loop with deterministic scanner-based verdicts\n"
            + "- SHA-256 hash-chained audit log\n"
            + "- Incident reports by on-device Ollama model (" + aegis.ai.LocalSecurityLLM.MODEL
            + ") — advisory only, never the security decision-maker.");
        about.getDialogPane().setMinWidth(520);
        about.showAndWait();
    }

    private void openDirectoryChooser() {
        DirectoryChooser chooser = new DirectoryChooser();
        chooser.setTitle("Select Workspace Directory");
        Path current = Paths.get(workspacePath.getText());
        if (Files.isDirectory(current)) {
            chooser.setInitialDirectory(current.toFile());
        }
        Window window = getScene().getWindow();
        java.io.File dir = chooser.showDialog(window);
        if (dir != null) {
            workspacePath.setText(dir.getAbsolutePath());
        }
    }

    private void runScan() {
        String path = workspacePath.getText().trim();
        if (path.isEmpty()) {
            appendLog("[ERROR] No workspace path specified.");
            return;
        }
        Path workspace = Paths.get(path);
        if (!Files.isDirectory(workspace)) {
            appendLog("[ERROR] Directory does not exist: " + path);
            verdictLabel.setText("INVALID PATH");
            verdictLabel.setTextFill(Color.RED);
            return;
        }

        scanButton.setDisable(true);
        progressBar.setVisible(true);
        progressBar.setProgress(-1);
        logOutput.clear();
        findingsPanel.getChildren().clear();
        lastFindings = new ArrayList<>();
        verdictLabel.setText("Scanning...");
        verdictLabel.setTextFill(Color.YELLOW);
        updateStats(0, 0);
        appendLog("Aegis PreFlight " + VERSION + " — Security Scan (fully offline after one-time setup)");
        appendLog("Started: " + Instant.now());
        appendLog("Workspace: " + path);
        appendLog("");

        boolean doConfig = configCheck.isSelected();

        new Thread(() -> {
            List<Finding> findings = new ArrayList<>();

            // Deterministic PreFlight pipeline — same engines as the headless
            // gate: Gitleaks (secrets) + Semgrep (SAST, bundled rules) +
            // Trivy (CVEs, cached DB). Fully offline, exit-code driven.
            appendLog("[1/2] PreFlight scanners: Gitleaks + Semgrep + Trivy (offline)...");
            aegis.preflight.ScanEngine engine = new aegis.preflight.ScanEngine(workspace);
            try {
                List<aegis.preflight.ScanResult> results = engine.scanAll();
                for (aegis.preflight.ScanResult r : results) {
                    String status = r.isScannerAvailable()
                        ? r.getVerdict() + ", " + r.findingCount() + " finding(s)"
                        : "UNAVAILABLE";
                    appendLog(String.format("    %s -> %s (%dms)",
                        r.getScannerName(), status, r.getDuration().toMillis()));
                    findings.addAll(r.getFindings());
                }
            } catch (Exception e) {
                appendLog("  [ERROR] PreFlight scan failed: " + e.getMessage());
            }

            if (doConfig) {
                appendLog("[2/2] Config & Sensitive File Analysis...");
                scanConfig(workspace, findings);
            } else {
                appendLog("[2/2] Config analysis skipped.");
            }

            int total = findings.size();
            int blockers = (int) findings.stream().filter(f -> f.toVerdict() == Verdict.BLOCK).count();

            Verdict verdict = Verdict.PASS;
            for (Finding f : findings) {
                verdict = verdict.mergeWith(f.toVerdict());
            }

            final Verdict finalVerdict = verdict;
            final List<Finding> finalFindings = findings;

            Platform.runLater(() -> {
                lastFindings = finalFindings;
                displayFindings(finalFindings);
                updateStats(total, blockers);
                scanButton.setDisable(false);
                progressBar.setProgress(1.0);
                progressBar.setVisible(false);

                appendLog("");
                appendLog("=== Scan Complete ===");
                appendLog("Verdict: " + finalVerdict);
                appendLog("Findings: " + total);
                appendLog("Blockers: " + blockers);

                verdictLabel.setText(finalVerdict.name());
                switch (finalVerdict) {
                    case PASS -> verdictLabel.setTextFill(Color.LAWNGREEN);
                    case WARNING -> verdictLabel.setTextFill(Color.ORANGE);
                    case BLOCK -> verdictLabel.setTextFill(Color.RED);
                }

                // Security Report: on-device LLM, advisory only, never gates BLOCK/PASS.
                // 5s timeout — falls back to raw structured findings on failure.
                securityReportPane.setExpanded(true);
                securityReport.setText("Generating incident report on-device ("
                    + aegis.ai.LocalSecurityLLM.MODEL + ", localhost:11434)...");
            });

            Thread reportThread = new Thread(() -> {
                // Stage 1: single 5s attempt — instant structured fallback if
                // the model is cold/slow/absent. The UI is NEVER blocked.
                String report = aegis.ai.LocalSecurityLLM.generateReportOffline(
                    finalFindings, List.of());
                String initialText = report != null
                    ? report
                    : aegis.ai.LocalSecurityLLM.structuredFallback(finalFindings, List.of());
                Platform.runLater(() -> {
                    securityReport.setText(initialText);
                    appendLog("[security-report] displayed "
                        + (report != null ? "on-device LLM explanation" : "structured fallback"
                            + " (model warming up — will upgrade in place)"));
                });

                // Stage 2 (background only): if stage 1 fell back, keep trying
                // within a bounded budget until Ollama finishes loading; then
                // upgrade the card to the real LLM narrative in place.
                if (report == null) {
                    String upgraded = aegis.ai.LocalSecurityLLM.generateReportOffline(
                        finalFindings, List.of(), 120_000);
                    if (upgraded != null) {
                        Platform.runLater(() -> {
                            securityReport.setText(upgraded);
                            appendLog("[security-report] upgraded to on-device LLM explanation");
                            dumpReportIfRequested(upgraded);
                            captureScreenshotIfRequested();
                        });
                    } else {
                        Platform.runLater(() -> {
                            dumpReportIfRequested(initialText);
                            captureScreenshotIfRequested();
                        });
                    }
                } else {
                    Platform.runLater(() -> {
                        dumpReportIfRequested(report);
                        captureScreenshotIfRequested();
                    });
                }
            }, "llm-report-thread");
            reportThread.setDaemon(true);
            reportThread.start();
        }, "scan-thread").start();
    }

    private void scanConfig(Path root, List<Finding> findings) {
        int sensitiveCount = 0;
        try (Stream<Path> files = Files.walk(root)) {
            files.filter(Files::isRegularFile)
                 .filter(p -> !isIgnored(p))
                 .forEach(file -> {
                     String name = file.getFileName().toString().toLowerCase();
                     if (SENSITIVE_EXTENSIONS.contains(getExtension(name))) {
                         String rel = root.relativize(file).toString();
                         findings.add(new Finding(
                             Finding.FindingType.CONFIG,
                             Finding.Severity.HIGH,
                             "local-regex",
                             rel, 0,
                             "Sensitive file detected (" + name + "). Ensure it is not committed to version control."
                         ));
                     }
                     if (name.equals(".env") || name.endsWith(".env.local") || name.endsWith(".env.production")) {
                         String rel = root.relativize(file).toString();
                         findings.add(new Finding(
                             Finding.FindingType.CONFIG,
                             Finding.Severity.HIGH,
                             "local-regex",
                             rel, 0,
                             "Environment file detected. Add to .gitignore."
                         ));
                     }
                     if (name.equals("docker-compose.yml") || name.equals("docker-compose.yaml")) {
                         try {
                             String content = Files.readString(file);
                             if (content.contains(" privileged: true") || content.contains("privileged: true")) {
                                 String rel = root.relativize(file).toString();
                                 findings.add(new Finding(
                                     Finding.FindingType.CONFIG,
                                     Finding.Severity.MEDIUM,
                                     "local-regex",
                                     rel, 0,
                                     "Docker Compose uses privileged mode. Review for security."
                                 ));
                             }
                         } catch (IOException ignored) {}
                     }
                 });
        } catch (IOException e) {
            appendLog("  [WARN] Could not scan configs: " + e.getMessage());
        }
        appendLog("  -> Sensitive file scan complete.");
    }

    private boolean isIgnored(Path p) {
        String pathStr = p.toString();
        return pathStr.contains("/.git/") || pathStr.contains("/node_modules/")
            || pathStr.contains("/target/") || pathStr.contains("/.idea/")
            || pathStr.contains("/__pycache__/") || pathStr.contains("/.gradle/")
            || pathStr.endsWith(".class") || pathStr.endsWith(".jar");
    }

    private String getExtension(String filename) {
        int dot = filename.lastIndexOf('.');
        return dot >= 0 ? filename.substring(dot) : "";
    }

    private void updateStats(int findings, int blockers) {
        findingsCountLabel.setText("Findings: " + findings);
        blockersCountLabel.setText("Blockers: " + blockers);
        if (blockers > 0) {
            blockersCountLabel.setTextFill(Color.RED);
        } else {
            blockersCountLabel.setTextFill(Color.LIGHTGRAY);
        }
    }

    private void displayFindings(List<Finding> findings) {
        findingsPanel.getChildren().clear();
        if (findings.isEmpty()) {
            Label noFindings = new Label("No findings detected. Workspace looks clean.");
            noFindings.setTextFill(Color.LAWNGREEN);
            noFindings.setWrapText(true);
            findingsPanel.getChildren().add(noFindings);
            return;
        }
        for (Finding f : findings) {
            Label lbl = new Label(String.format("[%s/%s] %s:%d\n  %s",
                f.type(), f.severity(), f.file(), f.line(), f.remediation()));
            lbl.setWrapText(true);
            lbl.setFont(Font.font("Monospaced", 11));
            lbl.setPadding(new Insets(4, 6, 4, 6));
            lbl.setStyle("-fx-background-radius: 4; -fx-background-color: #1a1a2e;");
            switch (f.severity()) {
                case CRITICAL -> lbl.setTextFill(Color.RED);
                case HIGH -> lbl.setTextFill(Color.DARKORANGE);
                case MEDIUM -> lbl.setTextFill(Color.ORANGE);
                case LOW -> lbl.setTextFill(Color.YELLOW);
                default -> lbl.setTextFill(Color.LIGHTGRAY);
            }
            findingsPanel.getChildren().add(lbl);
        }
    }

    private void appendLog(String message) {
        Platform.runLater(() -> {
            logOutput.appendText(message + "\n");
            if (logOutput.getText().split("\n", -1).length > MAX_LOG_LINES) {
                String text = logOutput.getText();
                int idx = text.indexOf('\n');
                if (idx > 0) {
                    logOutput.setText(text.substring(idx + 1));
                }
            }
        });
    }

    private Label label(String text, boolean small) {
        Label l = new Label(text);
        l.setFont(Font.font("System", FontWeight.SEMI_BOLD, small ? 11 : 13));
        l.setTextFill(Color.LIGHTGRAY);
        return l;
    }

    private VBox buildTitle() {
        Label title = new Label("Aegis PreFlight");
        title.setFont(Font.font("System", FontWeight.BOLD, 18));
        title.setTextFill(Color.WHITE);
        Label subtitle = new Label("Security for AI Coding");
        subtitle.setFont(Font.font("System", 12));
        subtitle.setTextFill(Color.LIGHTGRAY);
        return new VBox(2, title, subtitle);
    }
}
