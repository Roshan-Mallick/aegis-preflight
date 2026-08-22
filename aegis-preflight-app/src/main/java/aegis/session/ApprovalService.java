package aegis.session;

import aegis.audit.AuditException;
import aegis.audit.AuditLogger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Consumer;

/**
 * Pending-approval queue for commands the {@link aegis.policy.CommandGate}
 * held with REQUIRE_APPROVAL.
 *
 * Flow:
 *   gate holds command  ->  {@link #submit}  ->  UI shows SECURITY APPROVAL REQUIRED card
 *   Approve -> {@link #approve}     : row APPROVAL_GRANTED, command executes via callback
 *   Deny    -> {@link #deny}        : row DEVELOPER_OVERRIDE, command never executes
 *
 * The UI listener receives the full pending snapshot on every change;
 * SessionManager wraps it in Platform.runLater so card updates stay on the
 * JavaFX application thread.
 */
public class ApprovalService {

    private static final Logger log = LoggerFactory.getLogger(ApprovalService.class);

    /** One held command awaiting a human decision. */
    public record PendingRequest(
        String id,
        String sessionId,
        String command,
        String reason,
        Instant requestedAt
    ) {
    }

    private final AuditLogger audit;
    private final Consumer<PendingRequest> onApproved;
    private final Consumer<PendingRequest> onDenied;
    private final Consumer<List<PendingRequest>> uiListener;

    private final Map<String, PendingRequest> pending = new LinkedHashMap<>();

    public ApprovalService(AuditLogger audit,
                           Consumer<PendingRequest> onApproved,
                           Consumer<PendingRequest> onDenied,
                           Consumer<List<PendingRequest>> uiListener) {
        this.audit = audit;
        this.onApproved = onApproved == null ? r -> { } : onApproved;
        this.onDenied = onDenied == null ? r -> { } : onDenied;
        this.uiListener = uiListener == null ? l -> { } : uiListener;
    }

    /**
     * Queues a held command. Returns its approval id; does NOT execute.
     * (The APPROVAL_REQUESTED audit row is written by the CommandGate decision
     * logging — this method intentionally avoids a duplicate.)
     */
    public synchronized String submit(String sessionId, String command, String reason) {
        String id = "APR-" + UUID.randomUUID().toString().substring(0, 8);
        pending.put(id, new PendingRequest(id, sessionId, command, reason, Instant.now()));
        log.info("Command queued for approval {}: {}", id, command);
        notifyUi();
        return id;
    }

    /**
     * Human approved the held command: persists APPROVAL_GRANTED, removes it
     * from the queue and hands it to the executor callback (which runs it via
     * execStreaming). Returns false if the request no longer exists.
     */
    public synchronized boolean approve(String requestId, String user) {
        PendingRequest request = pending.remove(requestId);
        if (request == null) {
            return false;
        }
        if (Boolean.getBoolean("aegis.selftest")) {
            log.info("[TRACE] approve({}) user={}", requestId, user,
                new Exception("who-called-approve"));
        }
        try {
            audit.logApprovalGranted(request.command(), user);
        } catch (AuditException e) {
            log.warn("Failed to persist approval-granted event: {}", e.getMessage());
        }
        notifyUi();
        onApproved.accept(request);
        return true;
    }

    /**
     * Human denied the held command: persists DEVELOPER_OVERRIDE, removes it
     * from the queue and notifies the UI. The command never executes.
     * Returns false if the request no longer exists.
     */
    public synchronized boolean deny(String requestId, String user, String justification) {
        PendingRequest request = pending.remove(requestId);
        if (request == null) {
            return false;
        }
        try {
            audit.logApprovalDenied(request.command(), user, justification);
        } catch (AuditException e) {
            log.warn("Failed to persist approval-denied event: {}", e.getMessage());
        }
        notifyUi();
        onDenied.accept(request);
        return true;
    }

    public synchronized List<PendingRequest> snapshot() {
        return List.copyOf(pending.values());
    }

    public synchronized boolean hasPendingFor(String sessionId) {
        return pending.values().stream().anyMatch(r -> r.sessionId().equals(sessionId));
    }

    private void notifyUi() {
        uiListener.accept(new ArrayList<>(pending.values()));
    }
}
