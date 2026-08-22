package aegis.gui;

import aegis.monitor.ActivityEvent;
import aegis.session.SessionManager;
import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.Tab;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;
import javafx.scene.paint.Color;
import javafx.scene.text.Font;

import java.nio.file.Path;

/**
 * One guarded-terminal tab = one independent sandbox container.
 *
 * Console contract: input line -> SessionManager.submitCommand() ->
 * CommandGate decision. Only ALLOWed commands ever reach docker exec; BLOCK
 * and REQUIRE_APPROVAL outcomes are rendered here without execution.
 */
final class TerminalTab extends Tab implements SessionManager.StreamSink {

    private static final int MAX_OUTPUT_LINES = 2000;

    private final SessionManager sessions;
    private final TextArea output;
    private final TextField input;
    private final Label statusLabel;
    private final Button runButton;

    private final String sessionId;
    private final String containerName;

    private volatile boolean awaitingApproval;
    private volatile boolean commandRunning;

    private TerminalTab(SessionManager sessions, String sessionId, String containerName) {
        this.sessions = sessions;
        this.sessionId = sessionId;
        this.containerName = containerName;

        output = new TextArea();
        output.setEditable(false);
        output.setWrapText(false);
        output.setFont(Font.font("Monospaced", 12));
        output.getStyleClass().add("log-output");
        VBox.setVgrow(output, Priority.ALWAYS);

        statusLabel = new Label("RUNNING  " + containerName + " [" + sessionId + "]");
        statusLabel.setFont(Font.font("System", 11));
        statusLabel.setTextFill(Color.LIGHTGRAY);

        input = new TextField();
        input.setPromptText(
            "Type a command — evaluated by the Aegis gate before any docker exec");
        input.setFont(Font.font("Monospaced", 12));
        HBox.setHgrow(input, Priority.ALWAYS);

        runButton = new Button("Run");
        runButton.getStyleClass().add("scan-button");

        input.setOnAction(e -> submit());
        runButton.setOnAction(e -> submit());

        HBox inputRow = new HBox(6, input, runButton);
        inputRow.setAlignment(Pos.CENTER_LEFT);
        inputRow.setPadding(new Insets(6, 0, 0, 0));

        VBox root = new VBox(4, statusLabel, output, inputRow);
        root.setPadding(new Insets(8));
        setContent(root);

        // Closing the tab tears down BOTH the container and this session's
        // docker-events tailer process. MainLayout also watches the tab list
        // (covers programmatic removal, which does not fire onClosed).
        setOnClosed(e -> teardownSession());
    }

    /**
     * Factory: creates the tab with an already-started sandbox session.
     * Called on the FX thread; docker start takes a moment but keeps the flow
     * deterministic for callers (same synchronous style as runScan()).
     */
    static TerminalTab create(Path workspace, SessionManager sessions) throws Exception {
        TerminalTab[] holder = new TerminalTab[1];
        String sessionId = sessions.createSession(workspace,
            ev -> {
                if (ev != null && ev.flagged()) {
                    TerminalTab tab = holder[0];
                    if (tab != null) {
                        Platform.runLater(() -> tab.appendLine("[AEGIS MONITOR] FLAGGED "
                            + ev.kind().label() + ": " + ev.detail()
                            + "  (" + ev.rule() + ")"));
                    }
                }
            },
            null); // sink wired right after construction below
        TerminalTab tab = new TerminalTab(sessions, sessionId,
            sessions.getSession(sessionId).getContainerName());
        holder[0] = tab;
        sessions.attachSink(sessionId, tab);
        tab.setText("Term · " + workspace.getFileName() + " · " + sessionId);
        tab.appendLine("[AEGIS] Guarded terminal ready — container " + tab.containerName);
        tab.appendLine("[AEGIS] Every command passes the gate "
            + "(ALLOW / BLOCK / REQUIRE_APPROVAL) before execution.");
        return tab;
    }

    String getSessionId() {
        return sessionId;
    }

    /** Idempotent: container + docker-events tailer teardown for this tab. */
    void teardownSession() {
        sessions.closeSession(sessionId);
    }

    String getContainerName() {
        return containerName;
    }

    boolean isAwaitingApproval() {
        return awaitingApproval;
    }

    TextField inputFieldForTest() {
        return input;
    }

    /** Full console text (must be called on the FX thread). */
    String outputTextForTest() {
        return output.getText();
    }

    /** Submits the typed line to the pre-execution gate. */
    void submit() {
        String command = input.getText().strip();
        if (command.isEmpty()) {
            return;
        }
        appendLine("$ " + command);
        input.clear();
        try {
            sessions.submitCommand(sessionId, command);
        } catch (Exception e) {
            appendLine("[AEGIS] submit failed: " + e.getMessage());
        }
    }

    /* ------------------------- StreamSink callbacks ------------------------ */
    /* May be invoked from worker threads or the FX thread — everything is
     * funneled through Platform.runLater, same as MainLayout.appendLog. */

    @Override
    public void onLine(String line) {
        Platform.runLater(() -> appendLine(line));
    }

    @Override
    public void onCompleted(int exitCode) {
        Platform.runLater(() -> {
            appendLine("[exit " + exitCode + "]");
            commandRunning = false;
            awaitingApproval = false;
            refreshStatus(exitCode == 0 ? Color.LIGHTGRAY : Color.ORANGE);
        });
    }

    @Override
    public void onBlocked(String reason) {
        Platform.runLater(() -> {
            commandRunning = false;
            awaitingApproval = false;
            refreshStatus(Color.RED);
            appendLine("[AEGIS GATE] BLOCKED — " + reason);
        });
    }

    @Override
    public void onPending(String approvalId, String reason) {
        Platform.runLater(() -> {
            awaitingApproval = true;
            commandRunning = false;
            refreshStatus(Color.ORANGE);
            appendLine("[AEGIS GATE] HELD FOR APPROVAL (" + approvalId + ") — see the "
                + "SECURITY APPROVAL REQUIRED card");
        });
    }

    /* ------------------------------ internals ------------------------------ */

    private void refreshStatus(Color color) {
        String state = awaitingApproval ? "AWAITING APPROVAL"
            : (commandRunning ? "RUNNING CMD" : "IDLE");
        statusLabel.setText(state + "  " + containerName + " [" + sessionId + "]");
        statusLabel.setTextFill(color);
    }

    private void appendLine(String line) {
        output.appendText(line + "\n");
        trimIfNeeded();
    }

    /** Same capped-buffer pattern as MainLayout.appendLog. */
    private void trimIfNeeded() {
        String text = output.getText();
        if (text.lines().count() > MAX_OUTPUT_LINES) {
            int idx = text.indexOf('\n');
            if (idx > 0) {
                output.setText(text.substring(idx + 1));
            }
        }
    }
}
