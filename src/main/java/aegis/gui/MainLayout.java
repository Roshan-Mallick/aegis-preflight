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

    private final TextField workspacePath;
    private final TextArea logOutput;
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

    private static final Pattern SECRET_PATTERNS = Pattern.compile(
        "(?i)(api[_-]?key|secret[_-]?key|password|token|private[_-]?key|"
        + "aws[_-]?access[_-]?key|aws[_-]?secret|jdbc:|mysql://|postgres://|"
        + "mongodb://|redis://|Bearer\\s+[A-Za-z0-9]|sk-[A-Za-z0-9]{20,})"
    );

    private static final Set<String> SENSITIVE_EXTENSIONS = Set.of(
        ".pem", ".key", ".p12", ".pfx", ".jks", ".keystore"
    );

    public MainLayout() {
        setPadding(new Insets(0));

        workspacePath = new TextField(System.getProperty("user.home"));
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

        Label version = new Label("v1.0.0");
        version.setFont(Font.font("System", 10));
        version.setTextFill(Color.GRAY);

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
        VBox.setVgrow(findingsPane, Priority.ALWAYS);

        Label header = new Label("Scan Results");
        header.setFont(Font.font("System", FontWeight.BOLD, 16));

        VBox center = new VBox(8, header, logOutput, findingsPane);
        center.setPadding(new Insets(15));
        setCenter(center);
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
        appendLog("Aegis PreFlight v1.0.0 — Security Scan");
        appendLog("Started: " + Instant.now());
        appendLog("Workspace: " + path);
        appendLog("");

        boolean doSecrets = secretsCheck.isSelected();
        boolean doConfig = configCheck.isSelected();

        new Thread(() -> {
            List<Finding> findings = new ArrayList<>();

            if (doSecrets) {
                appendLog("[1/3] Secret Detection...");
                scanSecrets(workspace, findings);
            }

            if (doConfig) {
                appendLog("[2/3] Config & Sensitive File Analysis...");
                scanConfig(workspace, findings);
            }

            appendLog("[3/3] Workspace Summary...");
            scanWorkspaceSummary(workspace, findings);

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
            });
        }, "scan-thread").start();
    }

    private void scanSecrets(Path root, List<Finding> findings) {
        try (Stream<Path> files = Files.walk(root)) {
            files.filter(Files::isRegularFile)
                 .filter(p -> !isIgnored(p))
                 .forEach(file -> {
                     try {
                         List<String> lines = Files.readAllLines(file);
                         String rel = root.relativize(file).toString();
                         for (int i = 0; i < lines.size(); i++) {
                             String line = lines.get(i);
                             if (SECRET_PATTERNS.matcher(line).find()) {
                                 String type = classifySecret(line);
                                 findings.add(new Finding(
                                     Finding.FindingType.SECRET,
                                     Verdict.BLOCK == Verdict.BLOCK
                                         ? Finding.Severity.HIGH : Finding.Severity.HIGH,
                                     rel, i + 1,
                                     "Possible " + type + " found. Remove and use environment variables."
                                 ));
                             }
                         }
                     } catch (IOException ignored) {}
                 });
            int count = (int) findings.stream().filter(f -> f.type() == Finding.FindingType.SECRET).count();
            appendLog("  -> " + count + " potential secret(s) found.");
        } catch (IOException e) {
            appendLog("  [WARN] Could not walk directory: " + e.getMessage());
        }
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
                             rel, 0,
                             "Sensitive file detected (" + name + "). Ensure it is not committed to version control."
                         ));
                     }
                     if (name.equals(".env") || name.endsWith(".env.local") || name.endsWith(".env.production")) {
                         String rel = root.relativize(file).toString();
                         findings.add(new Finding(
                             Finding.FindingType.CONFIG,
                             Finding.Severity.HIGH,
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

    private void scanWorkspaceSummary(Path root, List<Finding> findings) {
        long[] stats = {0, 0};
        try (Stream<Path> files = Files.walk(root)) {
            files.filter(Files::isRegularFile)
                 .filter(p -> !isIgnored(p))
                 .forEach(file -> {
                     stats[0]++;
                     try {
                         stats[1] += Files.size(file);
                     } catch (IOException ignored) {}
                 });
        } catch (IOException e) {
            appendLog("  [WARN] Could not enumerate workspace: " + e.getMessage());
        }
        long kb = stats[1] / 1024;
        appendLog("  -> " + stats[0] + " files, " + (kb > 1024 ? (kb / 1024) + " MB" : kb + " KB"));
    }

    private String classifySecret(String line) {
        String lower = line.toLowerCase();
        if (lower.contains("aws")) return "AWS credential";
        if (lower.contains("api") && lower.contains("key")) return "API key";
        if (lower.contains("password") || lower.contains("passwd")) return "password";
        if (lower.contains("private") && lower.contains("key")) return "private key";
        if (lower.contains("token")) return "token";
        if (lower.contains("jdbc") || lower.contains("mysql") || lower.contains("postgres")) return "database connection string";
        return "secret";
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
