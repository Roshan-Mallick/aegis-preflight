package aegis.sandbox;

import aegis.audit.AuditException;
import aegis.audit.AuditLogger;
import aegis.monitor.ActivityEvent;
import aegis.monitor.ActivityMonitor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.function.Consumer;

/**
 * Entry gate (GATE 1: AEGIS).
 *
 * Launches the agent's Docker sandbox:
 *   docker run -d --name aegis-sandbox-xxxx --network=none --read-only
 *              --memory=512m --cpus=1 --tmpfs /tmp
 *              -v &lt;workspace&gt;:/workspace -w /workspace ubuntu:22.04 sleep infinity
 *
 * Filesystem is restricted to the bind-mounted /workspace (rootfs is
 * read-only), network is fully disabled, and every exec is observed by an
 * {@link ActivityMonitor}. Kill/suspend supported per spec.
 */
public class SandboxManager implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(SandboxManager.class);

    private final AuditLogger audit;
    private final Consumer<ActivityEvent> uiListener;

    private DockerSandbox sandbox;
    private ActivityMonitor monitor;
    private Path workspace;
    private NetworkPolicy policy;

    public SandboxManager(AuditLogger audit, Consumer<ActivityEvent> uiListener) {
        this.audit = audit;
        this.uiListener = uiListener == null ? e -> { } : uiListener;
    }

    /**
     * Starts the sandbox container and the activity monitor.
     */
    public synchronized void start(Path workspaceDir) throws SandboxException {
        if (sandbox != null && sandbox.isRunning()) {
            throw new SandboxException("Sandbox already running");
        }
        if (!Files.isDirectory(workspaceDir)) {
            throw new SandboxException("Workspace directory does not exist: " + workspaceDir);
        }

        this.workspace = workspaceDir.toAbsolutePath().normalize();
        this.policy = NetworkPolicy.NONE;
        this.sandbox = new DockerSandbox();

        sandbox.start(this.workspace, policy);

        this.monitor = new ActivityMonitor(
            sandbox.getContainerName(),
            false, // network is disabled — any attempt is flagged
            uiListener,
            flagged -> {
                try {
                    audit.logActivityFlagged(flagged.kind().label(), flagged.detail(),
                        flagged.rule() == null ? "RULE" : flagged.rule());
                } catch (AuditException e) {
                    log.warn("Failed to persist flagged activity: {}", e.getMessage());
                }
            });
        monitor.start();

        try {
            audit.logSandboxStart(sandbox.getContainerName(), this.workspace.toString(),
                policy.name());
        } catch (AuditException e) {
            log.warn("Failed to audit sandbox start: {}", e.getMessage());
        }

        log.info("SandboxManager started: {} for workspace {}", sandbox.getContainerName(), this.workspace);
    }

    /**
     * Runs a command inside the sandbox, capturing combined stdout/stderr.
     * Non-zero exits are returned as outcomes, not exceptions.
     */
    public synchronized DockerSandbox.ExecOutcome exec(String command) {
        requireStarted();
        DockerSandbox.ExecOutcome outcome = sandbox.execAllowFailure(command);
        if (monitor != null) {
            monitor.ingestAgentOutput(outcome.output());
            monitor.ingestProcessExec(command);
        }
        return outcome;
    }

    public void suspend() throws SandboxException {
        requireStarted();
        sandbox.pause();
    }

    public void resume() throws SandboxException {
        requireStarted();
        sandbox.unpause();
    }

    /** Hard kill per spec (docker kill). */
    public synchronized void kill(String reason) {
        if (sandbox == null) {
            return;
        }
        try {
            sandbox.kill();
            audit.logSandboxKill(sandbox.getContainerName(), reason);
        } catch (SandboxException e) {
            log.warn("Kill failed: {}", e.getMessage());
        } catch (AuditException e) {
            log.warn("Failed to audit kill: {}", e.getMessage());
        } finally {
            stopInternal();
        }
    }

    public synchronized void stop() {
        stopInternal();
    }

    private void stopInternal() {
        if (monitor != null) {
            monitor.close();
            monitor = null;
        }
        if (sandbox != null) {
            sandbox.stop();
            try {
                audit.logSandboxStop(sandbox.getContainerName());
            } catch (AuditException e) {
                log.debug("Failed to audit sandbox stop: {}", e.getMessage());
            }
            sandbox = null;
        }
    }

    public boolean isRunning() {
        return sandbox != null && sandbox.isRunning();
    }

    public String getContainerName() {
        return sandbox == null ? "(none)" : sandbox.getContainerName();
    }

    public Path getWorkspace() {
        return workspace;
    }

    public NetworkPolicy getPolicy() {
        return policy;
    }

    public ActivityMonitor getMonitor() {
        return monitor;
    }

    private void requireStarted() {
        if (sandbox == null || !sandbox.isRunning()) {
            throw new IllegalStateException("Sandbox not started");
        }
    }

    @Override
    public synchronized void close() {
        stopInternal();
    }
}
