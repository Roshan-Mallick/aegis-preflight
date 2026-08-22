package aegis.sandbox;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

public class DockerSandbox implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(DockerSandbox.class);
    private static final long EXEC_TIMEOUT_SECONDS = 120;

    private final String containerName;
    private String containerId;
    private boolean running;
    private NetworkPolicy activePolicy;

    public DockerSandbox() {
        this.containerName = "aegis-sandbox-" + UUID.randomUUID().toString().substring(0, 8);
    }

    public void start(Path workspaceDir, NetworkPolicy policy) throws SandboxException {
        if (running) {
            throw new SandboxException("Sandbox already running: " + containerName);
        }
        if (!Files.isDirectory(workspaceDir)) {
            throw new SandboxException("Workspace directory does not exist: " + workspaceDir);
        }

        List<String> cmd = new ArrayList<>();
        cmd.add("docker");
        cmd.add("run");
        cmd.add("-d");
        cmd.add("--name");
        cmd.add(containerName);

        if (policy.getDockerFlag() != null) {
            cmd.add(policy.getDockerFlag());
        } else {
            cmd.add("--network=none");
        }

        cmd.add("--memory=512m");
        cmd.add("--cpus=1");
        cmd.add("--read-only");
        cmd.add("--tmpfs");
        cmd.add("/tmp:size=64m");
        cmd.add("-v");
        cmd.add(workspaceDir.toAbsolutePath() + ":/workspace");
        cmd.add("-w");
        cmd.add("/workspace");
        cmd.add("ubuntu:22.04");
        cmd.add("sleep");
        cmd.add("infinity");

        try {
            containerId = execHostCommand(cmd);
            containerId = containerId.strip();
            running = true;
            activePolicy = policy;
            log.info("Sandbox started: {} (id={}, network={})", containerName, containerId, policy);
        } catch (Exception e) {
            throw new SandboxException("Failed to start sandbox: " + e.getMessage(), e);
        }
    }

    public void start(Path workspaceDir, List<String> dockerFlags) throws SandboxException {
        if (running) {
            throw new SandboxException("Sandbox already running: " + containerName);
        }
        if (!Files.isDirectory(workspaceDir)) {
            throw new SandboxException("Workspace directory does not exist: " + workspaceDir);
        }

        List<String> cmd = new ArrayList<>();
        cmd.add("docker");
        cmd.add("run");
        cmd.add("-d");
        cmd.add("--name");
        cmd.add(containerName);
        cmd.addAll(dockerFlags);

        try {
            containerId = execHostCommand(cmd);
            containerId = containerId.strip();
            running = true;
            activePolicy = NetworkPolicy.RESTRICTED;
            log.info("Sandbox started: {} (id={}, flags={} args)", containerName, containerId, dockerFlags.size());
        } catch (Exception e) {
            throw new SandboxException("Failed to start sandbox: " + e.getMessage(), e);
        }
    }

    public void start(Path workspaceDir) throws SandboxException {
        start(workspaceDir, NetworkPolicy.NONE);
    }

    public String execInContainer(String command) throws SandboxException {
        ensureRunning();

        List<String> cmd = List.of(
            "docker", "exec", containerName,
            "sh", "-c", command
        );

        try {
            String output = execHostCommand(cmd);
            log.debug("Exec in {}: {} -> {} chars", containerName, command, output.length());
            return output;
        } catch (Exception e) {
            throw new SandboxException("Exec failed in " + containerName + ": " + e.getMessage(), e);
        }
    }

    /**
     * Like {@link #execInContainer(String)} but returns captured stdout/stderr
     * even when the inner command exits non-zero. Needed for isolation probes
     * and agent commands whose failure output is the evidence we care about.
     */
    public ExecOutcome execAllowFailure(String command) {
        if (!running) {
            return new ExecOutcome(-1, "sandbox not running");
        }

        List<String> cmd = List.of(
            "docker", "exec", containerName,
            "sh", "-c", command
        );

        try {
            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.redirectErrorStream(true);
            Process process = pb.start();
            StringBuilder output = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (!output.isEmpty()) {
                        output.append('\n');
                    }
                    output.append(line);
                }
            }
            boolean finished = process.waitFor(EXEC_TIMEOUT_SECONDS, java.util.concurrent.TimeUnit.SECONDS);
            if (!finished) {
                process.destroyForcibly();
                return new ExecOutcome(-1, "timeout after " + EXEC_TIMEOUT_SECONDS + "s");
            }
            return new ExecOutcome(process.exitValue(), output.toString());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return new ExecOutcome(-1, "interrupted");
        } catch (IOException e) {
            return new ExecOutcome(-1, e.getMessage());
        }
    }

    public record ExecOutcome(int exitCode, String output) {
        public boolean success() {
            return exitCode == 0;
        }
    }

    /**
     * Default safety bound for {@link #execStreaming}: kill only after this
     * much ZERO-OUTPUT time — never a fixed wall-clock cap, so legitimately
     * long-running sessions that keep producing output are not cut off.
     */
    public static final long DEFAULT_IDLE_TIMEOUT_SECONDS = 900;

    private static final long EXIT_WAIT_AFTER_EOF_MS = 30_000;
    private static final long IDLE_WATCHER_POLL_MS = 5_000;

    /**
     * Runs a command inside the container and streams combined stdout/stderr
     * to {@code lineConsumer} LIVE, line by line (docker exec -i). Intended
     * for the guarded terminal's long-running/interactive command flow.
     *
     * Unlike {@link #execAllowFailure(String)} there is NO fixed 120s timeout:
     * the process is only killed if it emits nothing at all for longer than
     * the given idle window.
     *
     * @return the process exit code, or -1 if the sandbox is down or the
     *         stream failed/was idle-killed before completing normally.
     */
    public int execStreaming(String command, java.util.function.Consumer<String> lineConsumer,
                             long idleTimeoutSeconds) throws SandboxException {
        ensureRunning();
        Objects.requireNonNull(lineConsumer, "lineConsumer");

        List<String> cmd = List.of(
            "docker", "exec", "-i", containerName,
            "sh", "-c", command
        );

        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true);

        Process process;
        try {
            process = pb.start();
            // The guarded console submits COMPLETE commands — there is no
            // interactive stdin in this mode. Closing our end of stdin makes
            // `docker exec -i` terminate as soon as the inner command
            // finishes, instead of lingering forever on the open pipe.
            try {
                process.getOutputStream().close();
            } catch (IOException ignored) {
            }
        } catch (IOException e) {
            throw new SandboxException("Failed to start streaming exec in "
                + containerName + ": " + e.getMessage(), e);
        }

        AtomicLong lastActivity = new AtomicLong(System.currentTimeMillis());
        AtomicReference<IOException> streamFailure = new AtomicReference<>();

        // Idle watcher: kills the exec only when there has been no output at
        // all for longer than the idle window (hang protection secondary to
        // not killing legitimate long sessions).
        Thread watcher = new Thread(() -> {
            while (process.isAlive()) {
                long idleFor = System.currentTimeMillis() - lastActivity.get();
                if (idleFor > idleTimeoutSeconds * 1000L) {
                    log.warn("Streaming exec idle for {}ms — killing ({})",
                        idleFor, containerName);
                    process.destroyForcibly();
                    return;
                }
                try {
                    Thread.sleep(IDLE_WATCHER_POLL_MS);
                } catch (InterruptedException e) {
                    return;
                }
            }
        }, "exec-idle-watcher-" + containerName);
        watcher.setDaemon(true);
        watcher.start();

        int exitCode = -1;
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                lastActivity.set(System.currentTimeMillis());
                try {
                    lineConsumer.accept(line);
                } catch (RuntimeException consumerError) {
                    log.debug("lineConsumer threw — continuing stream: {}",
                        consumerError.getMessage());
                }
            }
        } catch (IOException e) {
            streamFailure.set(e);
            log.warn("Streaming exec output ended abnormally: {}", e.getMessage());
        }

        try {
            if (!process.waitFor(EXIT_WAIT_AFTER_EOF_MS, TimeUnit.MILLISECONDS)) {
                process.destroyForcibly();
            }
            exitCode = process.isAlive() ? -1 : process.exitValue();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            process.destroyForcibly();
        }
        watcher.interrupt();

        if (streamFailure.get() != null && exitCode == 0 && !running) {
            return -1;
        }
        return exitCode;
    }

    /** Convenience overload using {@link #DEFAULT_IDLE_TIMEOUT_SECONDS}. */
    public int execStreaming(String command, java.util.function.Consumer<String> lineConsumer)
            throws SandboxException {
        return execStreaming(command, lineConsumer, DEFAULT_IDLE_TIMEOUT_SECONDS);
    }

    /** docker pause — spec's suspend capability. */
    public void pause() throws SandboxException {
        ensureRunning();
        try {
            execHostCommand(List.of("docker", "pause", containerName));
            log.info("Sandbox suspended: {}", containerName);
        } catch (Exception e) {
            throw new SandboxException("Failed to suspend sandbox: " + e.getMessage(), e);
        }
    }

    /** docker unpause. */
    public void unpause() throws SandboxException {
        ensureRunning();
        try {
            execHostCommand(List.of("docker", "unpause", containerName));
            log.info("Sandbox resumed: {}", containerName);
        } catch (Exception e) {
            throw new SandboxException("Failed to resume sandbox: " + e.getMessage(), e);
        }
    }

    /** docker kill — hard stop without graceful shutdown. */
    public void kill() throws SandboxException {
        try {
            execHostCommand(List.of("docker", "kill", containerName));
            log.info("Sandbox killed: {}", containerName);
        } catch (Exception e) {
            throw new SandboxException("Failed to kill sandbox: " + e.getMessage(), e);
        }
    }

    public void revokeNetworkAccess() throws SandboxException {
        ensureRunning();

        try {
            execHostCommand(List.of(
                "docker", "network", "disconnect", "--force", "bridge", containerName
            ));
            activePolicy = NetworkPolicy.NONE;
            log.info("Network revoked for sandbox: {}", containerName);
        } catch (Exception e) {
            throw new SandboxException("Failed to revoke network: " + e.getMessage(), e);
        }
    }

    public void stop() {
        if (!running) {
            return;
        }
        try {
            execHostCommand(List.of("docker", "rm", "-f", containerName));
            log.info("Sandbox stopped: {}", containerName);
        } catch (Exception e) {
            log.warn("Failed to stop sandbox {}: {}", containerName, e.getMessage());
        } finally {
            running = false;
            containerId = null;
            activePolicy = null;
        }
    }

    public boolean isRunning() {
        if (!running) {
            return false;
        }
        try {
            String result = execHostCommand(List.of(
                "docker", "inspect", "-f", "{{.State.Running}}", containerName
            ));
            return "true".equals(result.strip());
        } catch (Exception e) {
            running = false;
            return false;
        }
    }

    public String getContainerName() {
        return containerName;
    }

    public NetworkPolicy getActivePolicy() {
        return activePolicy;
    }

    @Override
    public void close() {
        stop();
    }

    private void ensureRunning() throws SandboxException {
        if (!running) {
            throw new SandboxException("Sandbox not running: " + containerName);
        }
    }

    private String execHostCommand(List<String> command) throws IOException, InterruptedException {
        ProcessBuilder pb = new ProcessBuilder(command);
        pb.redirectErrorStream(true);

        Process process = pb.start();
        StringBuilder output = new StringBuilder();

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (!output.isEmpty()) {
                    output.append("\n");
                }
                output.append(line);
            }
        }

        boolean finished = process.waitFor(EXEC_TIMEOUT_SECONDS, TimeUnit.SECONDS);
        if (!finished) {
            process.destroyForcibly();
            throw new IOException("Command timed out after " + EXEC_TIMEOUT_SECONDS + "s: " + command);
        }

        int exitCode = process.exitValue();
        if (exitCode != 0) {
            throw new IOException("Command failed (exit=" + exitCode + "): " + output);
        }

        return output.toString();
    }
}
