package aegis.ai;

import aegis.monitor.ActivityEvent;
import aegis.preflight.Finding;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;

/**
 * Local LLM incident reporter (Ollama, on-device) — ADVISORY ONLY.
 *
 * Role per the original design doc, STRICTLY:
 *   1. Runtime behavioral analysis: consumes ActivityMonitor structured events
 *      (file access, process exec, network attempts, policy violations) and
 *      identifies suspicious combinations (e.g. sensitive file read +
 *      attempted external network call = possible exfiltration pattern).
 *   2. Incident report generation: turns structured findings from Gitleaks /
 *      Semgrep / Trivy plus sandbox violations into a human-readable
 *      explanation for the Security Report panel.
 *
 * It is NEVER part of the BLOCK/PASS decision. That gate is 100%
 * deterministic: scanner exit codes (Gitleaks/Semgrep/Trivy) + sandbox policy
 * violation flags, computed in VerdictEngine/RemediationLoop. This class has
 * NO write access to Finding.severity or Verdict — its only output is a
 * display String returned to the caller. If Ollama is down, slow (>5s), or
 * the model is missing, {@link #generateReportOffline} returns null and the
 * UI falls back to raw structured findings; the pipeline is never blocked.
 *
 * Fully offline: talks ONLY to localhost:11434. No other endpoint exists in
 * this file, no DNS names, no proxies.
 */
public final class LocalSecurityLLM {

    private static final Logger log = LoggerFactory.getLogger(LocalSecurityLLM.class);

    /** Confirmed locally available via `ollama list` during one-time setup. */
    public static final String MODEL = "llama3.2:3b";

    /** Loopback-only API of the local Ollama server started by OllamaManager. */
    public static final String API_URL = "http://localhost:11434/api/generate";

    /** Per design doc: must never block the pipeline longer than this. */
    public static final int TIMEOUT_SECONDS = 5;

    /**
     * Deterministic prompt template — instructs the model to explain the
     * structured evidence without speculation.
     */
    public static final String PROMPT_TEMPLATE =
        "You are a security analyst. Given this structured evidence, explain in 2-3 sentences "
        + "what happened and why it was flagged. Do not speculate beyond the evidence. "
        + "Evidence: %s";

    private static final Gson gson = new Gson();

    /**
     * Ollama runs ONE model instance — concurrent generate requests serialize
     * inside the server and starve each other's client-side timeouts. All
     * callers therefore queue here, so a single 5s attempt is spent on real
     * generation instead of waiting behind other requests.
     */
    private static final Object GENERATE_LOCK = new Object();

    /** Dedupe: identical evidence → identical report (no re-generation). */
    private static volatile String lastEvidenceJson;
    private static volatile String lastReportText;

    private LocalSecurityLLM() {
    }

    /**
     * Generates the human-readable incident report from structured evidence,
     * entirely on-device. Never throws: returns null on timeout/connection
     * failure/model error so callers fall back to raw structured findings.
     */
    public static String generateReportOffline(List<Finding> findings,
                                               List<ActivityEvent> sandboxEvents) {
        return generateReportOffline(findings, sandboxEvents, 0);
    }

    /**
     * Cold-start-aware variant. On a freshly booted machine Ollama needs
     * tens of seconds to load model weights BEFORE it can answer, so a single
     * 5-second attempt would always fall back on first run.
     *
     * Each HTTP attempt is still strictly capped at {@link #TIMEOUT_SECONDS}
     * (the UI is never blocked longer than one attempt — retries happen on a
     * background thread only). Within {@code totalBudgetMillis} the method
     * re-attempts every few seconds until the model is warm and a real
     * narrative comes back. Returns null if the budget is exhausted.
     */
    public static String generateReportOffline(List<Finding> findings,
                                               List<ActivityEvent> sandboxEvents,
                                               long totalBudgetMillis) {
        String evidence = buildEvidenceJson(findings, sandboxEvents);
        if (evidence.equals(lastEvidenceJson) && lastReportText != null) {
            return lastReportText;
        }
        long deadline = System.currentTimeMillis() + Math.max(0, totalBudgetMillis);
        int attempt = 0;
        do {
            attempt++;
            try {
                String prompt = String.format(PROMPT_TEMPLATE, evidence);
                String response = postGenerate(prompt);
                if (response != null && !response.isBlank()) {
                    if (attempt > 1) {
                        log.info("LocalSecurityLLM: report succeeded on attempt {} "
                            + "(model finished loading)", attempt);
                    }
                    log.info("LocalSecurityLLM: incident report generated on-device ({} chars)",
                        response.length());
                    lastEvidenceJson = evidence;
                    lastReportText = response.strip();
                    return response.strip();
                }
                log.warn("LocalSecurityLLM: empty response on attempt {}", attempt);
                return null; // server up but useless — do not spin
            } catch (java.net.http.HttpTimeoutException e) {
                log.warn("LocalSecurityLLM attempt {} timed out after {}s", attempt, TIMEOUT_SECONDS);
                if (System.currentTimeMillis() >= deadline) {
                    return null;
                }
                try {
                    Thread.sleep(5000); // leave the runner free while weights load
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    return null;
                }
            } catch (Exception e) {
                log.warn("LocalSecurityLLM unavailable ({}): {}",
                    e.getClass().getSimpleName(), e.getMessage());
                return null;
            }
        } while (System.currentTimeMillis() < deadline);
        return null;
    }

    /**
     * Deterministic fallback text used when the LLM times out or is absent —
     * renders the same structured findings without any generation.
     */
    public static String structuredFallback(List<Finding> findings,
                                            List<ActivityEvent> sandboxEvents) {
        StringBuilder sb = new StringBuilder();
        sb.append("On-device report generator unavailable — showing raw structured findings.\n\n");
        long flagged = sandboxEvents == null ? 0
            : sandboxEvents.stream().filter(ActivityEvent::flagged).count();
        sb.append("Sandbox policy violations: ").append(flagged).append('\n');
        if (findings == null || findings.isEmpty()) {
            sb.append("Scanner findings: none.");
            return sb.toString();
        }
        sb.append("Scanner findings: ").append(findings.size()).append('\n');
        int i = 1;
        for (Finding f : findings) {
            sb.append(i++).append(". [").append(f.tool()).append('/')
                .append(f.severity()).append("] ")
                .append(f.file()).append(':').append(f.line())
                .append(" — ").append(f.description()).append('\n');
        }
        return sb.toString();
    }

    /**
     * Loads the model into the Ollama runtime ahead of the first real report
     * so generation fits inside the 5-second budget. Fire-and-forget: any
     * failure is logged and ignored (the report path falls back gracefully).
     */
    public static void warmup() {
        try {
            postGenerate("Reply with the single word OK. Evidence: {}");
            log.info("LocalSecurityLLM: model '{}' warmed and resident", MODEL);
        } catch (Exception e) {
            log.warn("LocalSecurityLLM warmup failed (non-fatal): {}", e.getMessage());
        }
    }

    // --- evidence assembly (deterministic, structured) ---

    static String buildEvidenceJson(List<Finding> findings, List<ActivityEvent> sandboxEvents) {
        JsonObject evidence = new JsonObject();

        JsonArray findingsArr = new JsonArray();
        if (findings != null) {
            for (Finding f : findings) {
                JsonObject o = new JsonObject();
                o.addProperty("tool", f.tool());
                o.addProperty("type", f.type().name());
                o.addProperty("severity", f.severity().name());
                o.addProperty("file", f.file());
                o.addProperty("line", f.line());
                o.addProperty("description", f.description());
                findingsArr.add(o);
            }
        }
        evidence.add("scanner_findings", findingsArr);

        JsonArray eventsArr = new JsonArray();
        if (sandboxEvents != null) {
            for (ActivityEvent e : sandboxEvents) {
                JsonObject o = new JsonObject();
                o.addProperty("kind", e.kind().label());
                o.addProperty("detail", e.detail());
                if (e.flagged()) {
                    o.addProperty("flagged_rule", e.rule());
                }
                eventsArr.add(o);
            }
        }
        evidence.add("sandbox_events", eventsArr);

        long flaggedCount = sandboxEvents == null ? 0
            : sandboxEvents.stream().filter(ActivityEvent::flagged).count();
        evidence.addProperty("flagged_event_count", flaggedCount);
        evidence.addProperty("finding_count", findings == null ? 0 : findings.size());

        return gson.toJson(evidence);
    }

    // --- loopback HTTP ---

    private static String postGenerate(String prompt) throws Exception {
        JsonObject requestBody = new JsonObject();
        requestBody.addProperty("model", MODEL);
        requestBody.addProperty("prompt", prompt);
        requestBody.addProperty("stream", false);
        requestBody.add("options", gson.fromJson(
            "{\"temperature\":0,\"num_predict\":220}", JsonObject.class));

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(API_URL))
            .timeout(Duration.ofSeconds(TIMEOUT_SECONDS))
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(gson.toJson(requestBody)))
            .build();

        HttpResponse<String> response;
        synchronized (GENERATE_LOCK) {
            response = HttpClientHolder.CLIENT.send(request,
                HttpResponse.BodyHandlers.ofString());
        }

        if (response.statusCode() != 200) {
            log.warn("Ollama responded HTTP {}", response.statusCode());
            return null;
        }
        JsonObject body = gson.fromJson(response.body(), JsonObject.class);
        return body.has("response") && !body.get("response").isJsonNull()
            ? body.get("response").getAsString()
            : null;
    }

    /** Single shared client — HttpClient is thread-safe. */
    private static final class HttpClientHolder {
        private static final HttpClient CLIENT = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(TIMEOUT_SECONDS))
            .build();
    }
}
