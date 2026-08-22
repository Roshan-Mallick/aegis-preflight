package aegis.session;

import aegis.audit.AuditException;
import aegis.audit.AuditLogger;
import aegis.monitor.ActivityEvent;
import aegis.policy.CommandDecision;
import aegis.policy.CommandGate;
import aegis.policy.PolicyException;
import aegis.sandbox.SandboxException;
import aegis.sandbox.SandboxManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

/**
 * Owns one sandbox per guarded-terminal tab and the shared command gate +
 * approval flow. Replaces the old single-sandbox assumption: N tabs run N
 * independent containers concurrently, each with its own docker-events
 * tailer, all torn down when their tab closes.
 *
 * Command flow (pre-execution interception):
 *
 *   console input -> {@link CommandGate}.evaluate()
 *     ALLOW            -> execStreaming in worker thread, live output to tab
 *     BLOCK            -> never reaches docker exec; reason shown + TOOL_BLOCKED audit row
 *     REQUIRE_APPROVAL -> queued, APPROVAL card lists it until Approve/Deny
 */
public class SessionManager implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(SessionManager.class);

    /** Output/progress sink owned by one terminal tab (FX-thread safe). */
    public interface StreamSink {
        void onLine(String line);

        void onCompleted(int exitCode);

        /** Gate refused the command — it was never executed. */
        void onBlocked(String reason);

        /** Gate held the command for human review. */
        void onPending(String approvalId, String reason);
    }

    private final AuditLogger audit;
    private final CommandGate gate;
    private final ApprovalService approvals;

    private final Map<String, SandboxManager> sessions = new ConcurrentHashMap<>();
    private final Map<String, StreamSink> sinks = new ConcurrentHashMap<>();

    public SessionManager(AuditLogger audit,
                          Consumer<ActivityEvent> flaggedUiListener,
                          Consumer<List<ApprovalService.PendingRequest>> approvalCardListener)
            throws PolicyException {
        this.audit = audit;
        this.gate = CommandGate.loadDefault();
        this.approvals = new ApprovalService(
            audit,
            this::executeApproved,
            request -> routeToSink(request.sessionId(), s ->
                s.onLine("[AEGIS] Approval DENIED — '" + abbreviate(request.command())
                    + "' will not be executed.")),
            approvalCardListener == null ? l -> { } : approvalCardListener
        );
        log.info("SessionManager ready with bundled default policy");
    }

    /**
     * Starts a fresh sandbox container for a new terminal tab.
     *
     * @param activityListener receives this session's ActivityEvents
     *                         (flagged ones are also audited, as everywhere)
     */
    public synchronized String createSession(Path workspace,
                                             Consumer<ActivityEvent> activityListener,
                                             StreamSink sink) throws SandboxException {
        String sessionId = "S-" + UUID.randomUUID().toString().substring(0, 8);
        SandboxManager manager = new SandboxManager(audit, activityListener);
        manager.start(workspace);
        sessions.put(sessionId, manager);
        sinks.put(sessionId, sink == null ? new NullSink() : sink);
        log.info("Session {} started (container {})", sessionId, manager.getContainerName());
        return sessionId;
    }

    public SandboxManager getSession(String sessionId) {
        return sessions.get(sessionId);
    }

    /** Re-binds the output sink for a session (used by the terminal tab). */
    public void attachSink(String sessionId, StreamSink sink) {
        sinks.put(sessionId, sink == null ? new NullSink() : sink);
    }

    public List<String> activeSessionIds() {
        return new ArrayList<>(sessions.keySet());
    }

    public int activeSessionCount() {
        return sessions.size();
    }

    public ApprovalService getApprovalService() {
        return approvals;
    }

    public CommandGate getGate() {
        return gate;
    }

    /**
     * THE interception point: evaluates the command BEFORE any docker exec.
     * Only ALLOW commands ever reach {@link SandboxManager#execStreaming}.
     */
    public void submitCommand(String sessionId, String command) {
        if (Boolean.getBoolean("aegis.selftest")) {
            log.info("[TRACE] submitCommand({}) cmd={}", sessionId,
                abbreviate(command), new Exception("who-called-submit"));
        }
        SandboxManager manager = sessions.get(sessionId);
        if (manager == null || !manager.isRunning()) {
            routeToSink(sessionId, s -> {
                s.onLine("[AEGIS] Session is no longer running.");
                s.onCompleted(-1);
            });
            return;
        }

        CommandDecision decision = gate.evaluate(command);
        try {
            audit.logCommandDecision(command, decision, sessionId);
        } catch (AuditException e) {
            log.warn("Failed to persist command decision: {}", e.getMessage());
        }

        switch (decision) {
            case ALLOW -> executeInWorker(sessionId, manager, command);
            case BLOCK -> routeToSink(sessionId, s -> {
                s.onLine("[AEGIS GATE] BLOCKED — " + decision.reason());
                s.onLine("[AEGIS GATE] Command never reached docker exec.");
                s.onBlocked(decision.reason());
            });
            case REQUIRE_APPROVAL -> {
                String approvalId = approvals.submit(sessionId, command, decision.reason());
                routeToSink(sessionId, s -> {
                    s.onLine("[AEGIS GATE] HELD FOR APPROVAL (" + approvalId + ") — "
                        + decision.reason());
                    s.onPending(approvalId, decision.reason());
                });
            }
        }
    }

    /** Worker-thread streaming execution for an allowed command. */
    private void executeInWorker(String sessionId, SandboxManager manager, String command) {
        Thread worker = new Thread(() -> {
            long start = System.currentTimeMillis();
            try {
                int exitCode = manager.execStreaming(command, line ->
                    routeToSink(sessionId, s -> s.onLine(line)));
                try {
                    audit.logAgentRun(command, exitCode, 0, 0,
                        System.currentTimeMillis() - start);
                } catch (AuditException e) {
                    log.warn("Failed to persist agent-run event: {}", e.getMessage());
                }
                routeToSink(sessionId, s -> s.onCompleted(exitCode));
            } catch (SandboxException e) {
                routeToSink(sessionId, s -> {
                    s.onLine("[AEGIS] Execution failed: " + e.getMessage());
                    s.onCompleted(-1);
                });
            }
        }, "aegis-exec-" + sessionId);
        worker.setDaemon(true);
        worker.start();
    }

    /** ApprovalService callback: run the approved command via execStreaming. */
    private void executeApproved(ApprovalService.PendingRequest request) {
        SandboxManager manager = sessions.get(request.sessionId());
        if (manager == null || !manager.isRunning()) {
            log.warn("Approved command {} references dead session {}",
                request.id(), request.sessionId());
            return;
        }
        routeToSink(request.sessionId(), s ->
            s.onLine("[AEGIS] Approved — executing held command..."));
        executeInWorker(request.sessionId(), manager, request.command());
    }

    /** Closes one session's container AND its docker-events tailer process. */
    public synchronized void closeSession(String sessionId) {
        SandboxManager manager = sessions.remove(sessionId);
        sinks.remove(sessionId);
        if (manager != null) {
            manager.close(); // stops monitor (kills tailer) then docker rm -f
            log.info("Session {} closed", sessionId);
        }
    }

    @Override
    public synchronized void close() {
        for (String id : List.copyOf(sessions.keySet())) {
            closeSession(id);
        }
    }

    private void routeToSink(String sessionId, Consumer<StreamSink> action) {
        StreamSink sink = sinks.get(sessionId);
        if (sink != null) {
            action.accept(sink);
        }
    }

    private static String abbreviate(String s) {
        if (s == null) {
            return "";
        }
        return s.length() <= 80 ? s : s.substring(0, 77) + "...";
    }

    private static final class NullSink implements StreamSink {
        @Override public void onLine(String line) { }
        @Override public void onCompleted(int exitCode) { }
        @Override public void onBlocked(String reason) { }
        @Override public void onPending(String approvalId, String reason) { }
    }
}
