package aegis.ai;

import aegis.preflight.Finding;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

public class OllamaClient {

    private static final Logger log = LoggerFactory.getLogger(OllamaClient.class);
    private static final Gson gson = new Gson();
    private static final String DEFAULT_MODEL = "llama3.2";
    private static final String API_URL = "http://localhost:11434/api/generate";
    private static final int TIMEOUT_SECONDS = 60;

    private final HttpClient httpClient;
    private final String model;

    public OllamaClient() {
        this(DEFAULT_MODEL);
    }

    public OllamaClient(String model) {
        this.model = model;
        this.httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();
        log.info("OllamaClient initialized: model={}, api={}", model, API_URL);
    }

    public String explainFinding(Finding finding) throws AiException {
        String prompt = buildFindingPrompt(finding);
        return generate(prompt);
    }

    public String explainFindings(java.util.List<Finding> findings) throws AiException {
        StringBuilder context = new StringBuilder();
        for (int i = 0; i < findings.size(); i++) {
            Finding f = findings.get(i);
            context.append(i + 1).append(". ")
                .append(f.type()).append(" / ").append(f.severity()).append("\n")
                .append("   File: ").append(f.file()).append(":").append(f.line()).append("\n")
                .append("   Fix: ").append(f.remediation()).append("\n\n");
        }

        String prompt = "You are a security advisor for a developer. "
            + "Explain the following security findings in plain English. "
            + "For each finding, explain what the risk is and why it matters, "
            + "in 1-2 sentences. Be direct and practical.\n\n"
            + "Findings:\n" + context;

        return generate(prompt);
    }

    public String explainVerdict(aegis.preflight.Verdict verdict,
                                  java.util.List<Finding> findings) throws AiException {
        String prompt = "You are a security advisor. "
            + "A PreFlight security scan returned verdict: " + verdict + ".\n"
            + "There are " + findings.size() + " finding(s).\n\n"
            + "Write a 2-3 sentence summary for the developer explaining:\n"
            + "1. What the overall security status means\n"
            + "2. What they should do next\n"
            + "Be direct and practical. No jargon.";

        return generate(prompt);
    }

    public String generate(String prompt) throws AiException {
        try {
            JsonObject requestBody = new JsonObject();
            requestBody.addProperty("model", model);
            requestBody.addProperty("prompt", prompt);
            requestBody.addProperty("stream", false);

            String json = gson.toJson(requestBody);

            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(API_URL))
                .timeout(Duration.ofSeconds(TIMEOUT_SECONDS))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(json))
                .build();

            log.debug("Ollama request: model={}, promptLength={}", model, prompt.length());

            HttpResponse<String> response = httpClient.send(request,
                HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() != 200) {
                throw new AiException("Ollama returned HTTP " + response.statusCode()
                    + ": " + response.body());
            }

            JsonObject responseBody = JsonParser.parseString(response.body()).getAsJsonObject();
            String text = responseBody.get("response").getAsString();

            log.debug("Ollama response: {} chars", text.length());
            return text.strip();

        } catch (AiException e) {
            throw e;
        } catch (java.net.ConnectException e) {
            throw new AiException("Ollama not running at " + API_URL
                + ". Start Ollama with: ollama serve", e);
        } catch (java.net.http.HttpTimeoutException e) {
            throw new AiException("Ollama request timed out after " + TIMEOUT_SECONDS + "s", e);
        } catch (Exception e) {
            throw new AiException("Ollama request failed: " + e.getMessage(), e);
        }
    }

    public boolean isAvailable() {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:11434/api/tags"))
                .timeout(Duration.ofSeconds(5))
                .GET()
                .build();
            HttpResponse<String> response = httpClient.send(request,
                HttpResponse.BodyHandlers.ofString());
            return response.statusCode() == 200;
        } catch (Exception e) {
            return false;
        }
    }

    public String getModel() {
        return model;
    }

    private String buildFindingPrompt(Finding finding) {
        return "You are a security advisor for a developer. "
            + "Explain the following security finding in plain English. "
            + "Explain what the risk is, why it matters, and what to do about it. "
            + "Be direct and practical in 2-3 sentences.\n\n"
            + "Type: " + finding.type() + "\n"
            + "Severity: " + finding.severity() + "\n"
            + "File: " + finding.file() + ":" + finding.line() + "\n"
            + "Remediation: " + finding.remediation();
    }
}
