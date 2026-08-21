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
 * display String returned to the caller. If Ollama is down, slow, or the
 * model is missing, {@link #generateReportOffline} returns null and the UI
 * falls back to the deterministic structured report below; the pipeline is
 * never blocked or errored because of it.
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

    /**
     * Per-attempt HTTP cap, overridable via -Daegis.llm.timeout-secs. Sized for
     * COLD STARTS: right after boot Ollama loads model weights into RAM before
     * the first token appears, which routinely exceeds 10s. All calls run on
     * BACKGROUND threads only — the UI always shows the instant deterministic
     * fallback and is never blocked by this value.
     */
    public static final int TIMEOUT_SECONDS =
        Integer.getInteger("aegis.llm.timeout-secs", 25);

    /** Bounded retry budget for the cold-start window (a few attempts, not forever). */
    public static final int MAX_ATTEMPTS = 5;

    /** Progressive backoff between cold-start attempts (ms). */
    private static final long[] BACKOFF_MILLIS = {3_000, 8_000, 15_000, 25_000};

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
     * tens of seconds to load model weights BEFORE it can answer.
     *
     * Each HTTP attempt is capped at {@link #TIMEOUT_SECONDS}; retries happen
     * on the CALLER's background thread only, at most {@link #MAX_ATTEMPTS}
     * times and never past {@code totalBudgetMillis}. Progressive backoff
     * leaves the server free while weights load. Returns null if attempts or
     * budget are exhausted — callers then keep their structured fallback
     * permanently for the session (silently; the fallback is a complete,
     * correct report on its own).
     */
    public static String generateReportOffline(List<Finding> findings,
                                               List<ActivityEvent> sandboxEvents,
                                               long totalBudgetMillis) {
        String evidence = buildEvidenceJson(findings, sandboxEvents);
        if (evidence.equals(lastEvidenceJson) && lastReportText != null) {
            return lastReportText;
        }
        long deadline = System.currentTimeMillis() + Math.max(0, totalBudgetMillis);
        for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
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
                return null; // server up but returned nothing useful — do not spin
            } catch (java.net.http.HttpTimeoutException e) {
                // Most common cold-start signal: request aborted while weights load.
                log.warn("LocalSecurityLLM attempt {}/{} timed out after {}s",
                    attempt, MAX_ATTEMPTS, TIMEOUT_SECONDS);
            } catch (Exception e) {
                // Connection refused/reset etc. — the server may itself still
                // be starting up; stay inside the same bounded retry budget.
                log.warn("LocalSecurityLLM unavailable on attempt {}/{} ({}): {}", attempt,
                    MAX_ATTEMPTS, e.getClass().getSimpleName(), e.getMessage());
            }
            if (attempt == MAX_ATTEMPTS || System.currentTimeMillis() >= deadline) {
                break;
            }
            long sleepMs = BACKOFF_MILLIS[Math.min(attempt - 1, BACKOFF_MILLIS.length - 1)];
            try {
                Thread.sleep(sleepMs); // background only — UI stays responsive
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                return null;
            }
        }
        log.warn("LocalSecurityLLM: cold-start budget exhausted after {} attempt(s); "
            + "structured fallback remains the final report for this session", MAX_ATTEMPTS);
        return null;
    }

    /**
     * Deterministic structured report used instantly on scan completion and
     * kept as the final state if the LLM never answers — built purely from
     * scanner output (tool/rule, file, line, severity, plain-language fix),
     * so it is a complete and correct report on its own.
     */
    public static String structuredFallback(List<Finding> findings,
                                            List<ActivityEvent> sandboxEvents) {
        StringBuilder sb = new StringBuilder();
        sb.append("Structured report (deterministic — generated locally, no LLM needed):\n\n");
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
     * so generation succeeds on the first background attempt. Fire-and-forget:
     * any failure is logged and ignored (the report path falls back gracefully).
     * Deliberately does NOT touch the report dedupe cache and uses the same
     * bounded retry pattern as reports, so a genuinely cold model finishes
     * loading here instead of failing silently.
     */
    public static void warmup() {
        long deadline = System.currentTimeMillis() + 90_000;
        for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
            try {
                postGenerate("Reply with the single word OK.");
                log.info("LocalSecurityLLM: model '{}' warmed and resident (attempt {})", MODEL, attempt);
                return;
            } catch (java.net.http.HttpTimeoutException e) {
                log.warn("LocalSecurityLLM warmup attempt {}/{} timed out ({}s) — weights still loading",
                    attempt, MAX_ATTEMPTS, TIMEOUT_SECONDS);
            } catch (Exception e) {
                log.warn("LocalSecurityLLM warmup failed (non-fatal): {}", e.getMessage());
                return;
            }
            if (System.currentTimeMillis() >= deadline) {
                break;
            }
            try {
                Thread.sleep(BACKOFF_MILLIS[Math.min(attempt - 1, BACKOFF_MILLIS.length - 1)]);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                return;
            }
        }
        log.warn("LocalSecurityLLM warmup did not complete (non-fatal); "
            + "report path will retry within its own budget");
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
