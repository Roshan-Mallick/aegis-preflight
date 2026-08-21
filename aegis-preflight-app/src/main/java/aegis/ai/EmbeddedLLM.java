package aegis.ai;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

/**
 * Lifecycle manager for the LLM inference server that ships INSIDE the
 * application package (llama.cpp's llama-server + a quantized GGUF model).
 *
 * Nothing external is required: no Ollama install, no model download, no
 * network. The engine binds to loopback only and is started automatically
 * on first use (app launch or first report), then adopted/reused if a
 * healthy instance is already listening.
 *
 * Layout resolution for the bundled directory (engine + model):
 *   1. system property aegis.llm.dir
 *   2. environment variable AEGIS_LLM_DIR
 *   3. <resources root>/llm          (dev layout / deb both use this)
 *   4. /opt/aegis-preflight/llm      (deb install layout)
 *
 * Expected structure:
 *   <dir>/bin/llama-server (+ its libggml/libllama shared libs)
 *   <dir>/models/*.gguf    (exactly one model file)
 */
public final class EmbeddedLLM {

    private static final Logger log = LoggerFactory.getLogger(EmbeddedLLM.class);

    /** Loopback port of the embedded server (configurable, never remote). */
    public static final int BASE_PORT = Integer.getInteger("aegis.llm.port", 11434);

    /** Ports tried in order when the preferred one is occupied by another program. */
    private static final int PORT_ATTEMPTS = 5;

    private static final String HOST = "127.0.0.1";
    private static final int STARTUP_TIMEOUT_SECONDS = 120;
    private static final int STOP_TIMEOUT_SECONDS = 10;

    private static final EmbeddedLLM INSTANCE = new EmbeddedLLM();

    private final HttpClient httpClient = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(3))
        .build();

    private Process serverProcess;
    private boolean adoptedRunningServer;
    private volatile int activePort = -1;
    private String lastError;

    private EmbeddedLLM() {
    }

    public static EmbeddedLLM get() {
        return INSTANCE;
    }

    public synchronized boolean ensureStarted() {
        if (isHealthy(activePort)) {
            return true;
        }
        try {
            start();
            return activePort > 0 && isHealthy(activePort);
        } catch (Exception e) {
            lastError = e.getMessage();
            log.warn("Embedded LLM server could not start (non-fatal): {}", e.getMessage());
            return false;
        }
    }

    /** Loopback URL of the running server's chat endpoint; null if not started. */
    public static String chatUrl() {
        int port = INSTANCE.activePort;
        return port > 0 ? "http://" + HOST + ":" + port + "/v1/chat/completions" : null;
    }

    /**
     * Starts the bundled llama-server bound to loopback. Adopts an already
     * healthy instance; if the preferred port is occupied by a DIFFERENT
     * program (no valid /health answer), walks to the next port instead of
     * failing — the app must never lose its report because of a squatter.
     */
    public synchronized void start() throws AiException {
        for (int attempt = 0; attempt < PORT_ATTEMPTS; attempt++) {
            int port = BASE_PORT + attempt;
            if (isHealthy(port)) {
                adopted(port);
                log.info("Embedded LLM already healthy on {}:{} — reusing it", HOST, port);
                return;
            }

            Path dir = resolveDir();
            Path bin = dir.resolve("bin").resolve("llama-server");
            Path model = findModel(dir);

            if (!Files.isRegularFile(bin) || !Files.isExecutable(bin)) {
                throw new AiException("Bundled llama-server not found or not executable: " + bin);
            }

            List<String> cmd = List.of(
                bin.toString(),
                "-m", model.toString(),
                "--host", HOST,
                "--port", String.valueOf(port),
                "-c", "2048",
                "--no-webui"
            );
            log.info("Starting embedded LLM server on port {}: {} (model: {})",
                port, bin, model.getFileName());

            try {
                ProcessBuilder pb = new ProcessBuilder(cmd);
                pb.environment().put("LD_LIBRARY_PATH", dir.resolve("bin").toString());
                pb.redirectErrorStream(true);
                serverProcess = pb.start();

                Thread logThread = new Thread(() -> drain(serverProcess), "embedded-llm-log");
                logThread.setDaemon(true);
                logThread.start();

                awaitHealth(port);
                adopted(port);
                log.info("Embedded LLM server ready on {}:{} (pid={})", HOST, port,
                    serverProcess.pid());
                return;
            } catch (AiException e) {
                // Bind conflicts and slow loads both land here — stop this
                // instance and move to the next candidate port.
                killOwnProcess();
                lastError = e.getMessage();
                log.warn("Embedded LLM failed on port {} ({}); trying next port", port,
                    e.getMessage());
            } catch (Exception e) {
                killOwnProcess();
                throw new AiException("Failed to launch embedded LLM server: " + e.getMessage(), e);
            }
        }
        throw new AiException("No free port for embedded LLM in range "
            + BASE_PORT + "-" + (BASE_PORT + PORT_ATTEMPTS - 1));
    }

    private void adopted(int port) {
        activePort = port;
        adoptedRunningServer = serverProcess == null;
    }

    private void killOwnProcess() {
        if (serverProcess != null && serverProcess.isAlive()) {
            serverProcess.destroyForcibly();
        }
        serverProcess = null;
    }

    public synchronized void stop() {
        if (adoptedRunningServer) {
            log.info("Embedded LLM was adopted from an external owner — leaving it running");
            return;
        }
        killOwnProcess();
        activePort = -1;
        log.info("Embedded LLM server stopped");
    }

    /** True when something answers GET /health with HTTP 200 on the given loopback port. */
    public boolean isHealthy(int port) {
        if (port <= 0) {
            return false;
        }
        try {
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("http://" + HOST + ":" + port + "/health"))
                .timeout(Duration.ofSeconds(2))
                .GET()
                .build();
            HttpResponse<String> response = httpClient.send(request,
                HttpResponse.BodyHandlers.ofString());
            return response.statusCode() == 200;
        } catch (Exception e) {
            return false;
        }
    }

    /** Convenience probe of the currently active port. */
    public boolean isHealthy() {
        return isHealthy(activePort);
    }

    public String getLastError() {
        return lastError;
    }

    // --- internals ---

    /** Blocks until /health turns 200 on the given port (weights loaded). */
    private void awaitHealth(int port) throws AiException {
        long deadline = System.currentTimeMillis() + STARTUP_TIMEOUT_SECONDS * 1000L;
        while (System.currentTimeMillis() < deadline) {
            if (serverProcess != null && !serverProcess.isAlive()) {
                throw new AiException("server exited during startup (exit="
                    + serverProcess.exitValue() + ")");
            }
            if (isHealthy(port)) {
                return;
            }
            try {
                Thread.sleep(500);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new AiException("Interrupted while waiting for embedded LLM", e);
            }
        }
        throw new AiException("not healthy within " + STARTUP_TIMEOUT_SECONDS + "s");
    }

    private void drain(Process process) {
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                log.debug("llama-server: {}", line);
            }
        } catch (IOException ignored) {
            // stream closed on shutdown
        }
    }

    private Path resolveDir() {
        String prop = System.getProperty("aegis.llm.dir");
        if (prop != null && !prop.isBlank() && Files.isDirectory(Path.of(prop))) {
            return Path.of(prop).toAbsolutePath().normalize();
        }
        String env = System.getenv("AEGIS_LLM_DIR");
        if (env != null && !env.isBlank() && Files.isDirectory(Path.of(env))) {
            return Path.of(env).toAbsolutePath().normalize();
        }
        // Deb layout: <root>/resources AND <root>/llm are siblings.
        Path root = aegis.preflight.ExternalToolResolver.resourceRoot();
        Path sibling = root.getParent() == null ? null : root.getParent().resolve("llm");
        if (sibling != null && Files.isDirectory(sibling)) {
            return sibling.toAbsolutePath().normalize();
        }
        Path bundled = root.resolve("llm"); // dev/source layout
        if (Files.isDirectory(bundled)) {
            return bundled.toAbsolutePath().normalize();
        }
        return Path.of("/opt/aegis-preflight/llm");
    }

    private Path findModel(Path dir) throws AiException {
        Path models = dir.resolve("models");
        if (!Files.isDirectory(models)) {
            throw new AiException("Bundled model directory missing: " + models);
        }
        List<Path> ggufs = new ArrayList<>();
        try (Stream<Path> files = Files.list(models)) {
            files.filter(p -> p.getFileName().toString().toLowerCase().endsWith(".gguf"))
                .filter(p -> !p.getFileName().toString().endsWith(".sha256"))
                .forEach(ggufs::add);
        } catch (IOException e) {
            throw new AiException("Cannot list bundled models in " + models + ": " + e.getMessage(), e);
        }
        if (ggufs.size() != 1) {
            throw new AiException("Expected exactly one bundled .gguf model in " + models
                + ", found " + ggufs.size());
        }
        return ggufs.get(0);
    }
}
