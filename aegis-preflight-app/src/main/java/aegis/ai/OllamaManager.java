package aegis.ai;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.concurrent.TimeUnit;

public class OllamaManager {

    private static final Logger log = LoggerFactory.getLogger(OllamaManager.class);
    private static final String OLLAMA_HOST = "http://localhost:11434";
    private static final int STARTUP_TIMEOUT_SECONDS = 15;
    private static final int STARTUP_POLL_INTERVAL_MS = 500;
    private static final int STOP_TIMEOUT_SECONDS = 5;

    private Process ollamaProcess;
    private boolean adoptedExternalServer;
    private final HttpClient httpClient;

    public OllamaManager() {
        this.httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();
    }

    public synchronized void start() throws AiException {
        if (ollamaProcess != null && ollamaProcess.isAlive()) {
            log.info("Ollama server already running (pid={})", ollamaProcess.pid());
            return;
        }

        // A server may already be listening on loopback (systemd service,
        // previous session, manual start). Adopt it instead of failing on
        // the port conflict — it serves the exact same local-only API.
        if (isServerResponding()) {
            adoptedExternalServer = true;
            log.info("Ollama already listening on {} — adopting existing server", OLLAMA_HOST);
            return;
        }

        String ollamaBin = resolveOllamaBinary();
        log.info("Starting Ollama server: {}", ollamaBin);

        try {
            ProcessBuilder pb = new ProcessBuilder(ollamaBin, "serve");
            pb.redirectErrorStream(true);
            ollamaProcess = pb.start();

            Thread logThread = new Thread(() -> {
                try (BufferedReader reader = new BufferedReader(
                        new InputStreamReader(ollamaProcess.getInputStream()))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        log.debug("ollama: {}", line);
                    }
                } catch (Exception e) {
                    log.debug("Ollama log reader closed", e);
                }
            }, "ollama-log-reader");
            logThread.setDaemon(true);
            logThread.start();

            log.info("Ollama process started (pid={}), waiting for API...", ollamaProcess.pid());
            waitForServer();

            if (!ollamaProcess.isAlive()) {
                throw new AiException("Ollama process exited during startup (exit code: "
                    + ollamaProcess.exitValue() + ")");
            }

            log.info("Ollama server ready (pid={})", ollamaProcess.pid());

        } catch (AiException e) {
            throw e;
        } catch (Exception e) {
            throw new AiException("Failed to start Ollama: " + e.getMessage(), e);
        }
    }

    public synchronized void stop() {
        if (adoptedExternalServer) {
            log.info("Using externally managed Ollama server — leaving it running");
            return;
        }
        if (ollamaProcess == null) {
            log.info("No Ollama process to stop");
            return;
        }

        if (!ollamaProcess.isAlive()) {
            log.info("Ollama process already exited (code={})", ollamaProcess.exitValue());
            ollamaProcess = null;
            return;
        }

        log.info("Stopping Ollama server (pid={})...", ollamaProcess.pid());
        ollamaProcess.destroy();

        try {
            boolean exited = ollamaProcess.waitFor(STOP_TIMEOUT_SECONDS, TimeUnit.SECONDS);
            if (!exited) {
                log.warn("Ollama did not exit in {}s, force killing...", STOP_TIMEOUT_SECONDS);
                ollamaProcess.destroyForcibly();
                ollamaProcess.waitFor(3, TimeUnit.SECONDS);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            ollamaProcess.destroyForcibly();
        }

        log.info("Ollama server stopped");
        ollamaProcess = null;
    }

    public boolean isModelAvailable(String modelName) {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(OLLAMA_HOST + "/api/tags"))
                .timeout(Duration.ofSeconds(5))
                .GET()
                .build();

            HttpResponse<String> response = httpClient.send(request,
                HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() != 200) {
                return false;
            }

            JsonObject body = JsonParser.parseString(response.body()).getAsJsonObject();
            JsonArray models = body.getAsJsonArray("models");

            if (models == null) {
                return false;
            }

            for (int i = 0; i < models.size(); i++) {
                JsonObject model = models.get(i).getAsJsonObject();
                String name = model.get("name").getAsString();
                if (name.equals(modelName) || name.startsWith(modelName + ":")) {
                    log.info("Model '{}' found locally", modelName);
                    return true;
                }
            }

            log.info("Model '{}' not found locally", modelName);
            return false;

        } catch (Exception e) {
            log.warn("Failed to check model availability: {}", e.getMessage());
            return false;
        }
    }

    public void pullModel(String modelName) throws AiException {
        if (isModelAvailable(modelName)) {
            log.info("Model '{}' already available, skipping pull", modelName);
            return;
        }

        log.info("Pulling model '{}'... this may take several minutes", modelName);

        String ollamaBin = resolveOllamaBinary();

        try {
            ProcessBuilder pb = new ProcessBuilder(ollamaBin, "pull", modelName);
            pb.redirectErrorStream(true);
            Process pullProcess = pb.start();

            Thread pullLogThread = new Thread(() -> {
                try (BufferedReader reader = new BufferedReader(
                        new InputStreamReader(pullProcess.getInputStream()))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        log.info("ollama pull: {}", line);
                    }
                } catch (Exception e) {
                    log.debug("Pull log reader closed", e);
                }
            }, "ollama-pull-log");
            pullLogThread.setDaemon(true);
            pullLogThread.start();

            boolean finished = pullProcess.waitFor(15, TimeUnit.MINUTES);

            if (!finished) {
                pullProcess.destroyForcibly();
                throw new AiException("Model pull timed out after 15 minutes");
            }

            int exitCode = pullProcess.exitValue();
            if (exitCode != 0) {
                throw new AiException("Model pull failed with exit code: " + exitCode);
            }

            log.info("Model '{}' pulled successfully", modelName);

        } catch (AiException e) {
            throw e;
        } catch (Exception e) {
            throw new AiException("Failed to pull model: " + e.getMessage(), e);
        }
    }

    public void ensureModelReady(String modelName) throws AiException {
        if (!isModelAvailable(modelName)) {
            log.warn("Model '{}' is not installed. On a fresh machine, run: ollama pull {}",
                modelName, modelName);
            throw new AiException(
                "Model '" + modelName + "' is not available locally. "
                + "Please run 'ollama pull " + modelName + "' and restart the application.");
        }
    }

    public boolean isRunning() {
        return adoptedExternalServer || (ollamaProcess != null && ollamaProcess.isAlive());
    }

    /** True if something is already serving the Ollama API on loopback. */
    private boolean isServerResponding() {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(OLLAMA_HOST + "/api/version"))
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

    private void waitForServer() throws AiException {
        long deadline = System.currentTimeMillis() + (STARTUP_TIMEOUT_SECONDS * 1000L);

        while (System.currentTimeMillis() < deadline) {
            if (isServerResponding()) {
                log.debug("Ollama API responded");
                return;
            }

            try {
                Thread.sleep(STARTUP_POLL_INTERVAL_MS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new AiException("Interrupted while waiting for Ollama", e);
            }
        }

        throw new AiException(
            "Ollama server did not become available within " + STARTUP_TIMEOUT_SECONDS + "s. "
            + "Check if another process is using port 11434.");
    }

    private String resolveOllamaBinary() {
        String[] candidates = {
            System.getenv("OLLAMA_BIN"),
            System.getProperty("ollama.binary"),
            System.getProperty("user.home") + "/.ollama-install/bin/ollama",
            "/usr/local/bin/ollama",
            "/usr/bin/ollama"
        };

        for (String path : candidates) {
            if (path != null && !path.isEmpty()) {
                java.io.File f = new java.io.File(path);
                if (f.exists() && f.canExecute()) {
                    log.debug("Using Ollama binary: {}", path);
                    return path;
                }
            }
        }

        try {
            ProcessBuilder which = new ProcessBuilder("which", "ollama");
            Process p = which.start();
            String result = new String(p.getInputStream().readAllBytes()).strip();
            if (p.waitFor() == 0 && !result.isEmpty()) {
                log.debug("Found Ollama via which: {}", result);
                return result;
            }
        } catch (Exception e) {
            log.debug("which ollama failed", e);
        }

        throw new RuntimeException(
            "Ollama binary not found. Install Ollama or set OLLAMA_BIN environment variable.");
    }
}
