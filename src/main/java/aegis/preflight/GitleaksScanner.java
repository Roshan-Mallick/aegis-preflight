package aegis.preflight;

import aegis.sandbox.DockerSandbox;
import aegis.sandbox.SandboxException;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

public class GitleaksScanner {

    private static final Logger log = LoggerFactory.getLogger(GitleaksScanner.class);
    private static final Gson gson = new Gson();

    private final DockerSandbox sandbox;

    public GitleaksScanner(DockerSandbox sandbox) {
        this.sandbox = sandbox;
    }

    public ScanResult scan() throws ScannerException {
        Instant start = Instant.now();
        log.info("Gitleaks scan starting");

        if (!isGitleaksInstalled()) {
            log.warn("Gitleaks not installed in container, skipping");
            return unavailableResult(Duration.between(start, Instant.now()));
        }

        String cmd = "gitleaks detect"
            + " --source=/workspace"
            + " --report-format=json"
            + " --no-banner"
            + " --redact";

        String output;
        try {
            output = sandbox.execInContainer(cmd);
        } catch (SandboxException e) {
            throw new ScannerException("Gitleaks execution failed: " + e.getMessage(), e);
        }

        Duration duration = Duration.between(start, Instant.now());
        List<Finding> findings = parseGitleaksOutput(output);
        Verdict verdict = computeVerdict(findings);

        log.info("Gitleaks complete: {} findings, verdict={}", findings.size(), verdict);
        return new ScanResult("gitleaks", verdict, findings, duration, true, output);
    }

    public boolean isGitleaksInstalled() {
        try {
            String output = sandbox.execInContainer("which gitleaks 2>/dev/null");
            return output.strip().contains("gitleaks");
        } catch (SandboxException e) {
            return false;
        }
    }

    private List<Finding> parseGitleaksOutput(String json) {
        List<Finding> findings = new ArrayList<>();
        if (json == null || json.isBlank()) {
            return findings;
        }

        try {
            JsonArray results = gson.fromJson(json, JsonArray.class);
            if (results == null) {
                return findings;
            }

            for (JsonElement elem : results) {
                JsonObject obj = elem.getAsJsonObject();
                findings.add(parseGitleaksFinding(obj));
            }
        } catch (Exception e) {
            log.warn("Failed to parse gitleaks JSON: {}", e.getMessage());
        }

        return findings;
    }

    private Finding parseGitleaksFinding(JsonObject obj) {
        String ruleId = getStringOrDefault(obj, "RuleID", "unknown");
        String file = getStringOrDefault(obj, "File", "");
        int startLine = getIntOrDefault(obj, "StartLine", 0);
        String match = getStringOrDefault(obj, "Match", "");

        Finding.Severity severity = mapGitleaksSeverity(ruleId);
        String remediation = buildRemediation(ruleId, match, file);

        return new Finding(
            Finding.FindingType.SECRET,
            severity,
            file,
            startLine,
            remediation
        );
    }

    private String buildRemediation(String ruleId, String match, String file) {
        String masked = maskSecret(match);
        String ruleLower = ruleId.toLowerCase();

        if (ruleLower.contains("private-key")) {
            return "Remove the private key from " + file + ". "
                + "Add it to .gitignore and rotate the key immediately.";
        }
        if (ruleLower.contains("aws")) {
            return "Remove hardcoded AWS key " + masked + " from " + file + ". "
                + "Use environment variables or AWS IAM roles instead. "
                + "Rotate the key in AWS Console > IAM > Security credentials.";
        }
        if (ruleLower.contains("generic-api") || ruleLower.contains("api-key")) {
            return "Remove hardcoded API key " + masked + " from " + file + ". "
                + "Store in environment variable and reference via System.getenv().";
        }
        if (ruleLower.contains("password")) {
            return "Remove hardcoded password from " + file + ". "
                + "Use environment variable or secret manager (e.g., Vault, AWS Secrets Manager).";
        }
        if (ruleLower.contains("token")) {
            return "Remove hardcoded token " + masked + " from " + file + ". "
                + "Move to environment variable or .env file (add .env to .gitignore).";
        }
        return "Remove hardcoded secret " + masked + " from " + file + ". "
            + "Use environment variable or secret manager instead.";
    }

    private Finding.Severity mapGitleaksSeverity(String ruleId) {
        String lower = ruleId.toLowerCase();
        if (lower.contains("aws") || lower.contains("private-key") || lower.contains("api-key")) {
            return Finding.Severity.CRITICAL;
        }
        if (lower.contains("generic-api") || lower.contains("password")) {
            return Finding.Severity.HIGH;
        }
        if (lower.contains("generic") || lower.contains("token")) {
            return Finding.Severity.MEDIUM;
        }
        return Finding.Severity.LOW;
    }

    private String maskSecret(String secret) {
        if (secret == null || secret.length() <= 8) {
            return "***";
        }
        return secret.substring(0, 4) + "..." + secret.substring(secret.length() - 4);
    }

    private Verdict computeVerdict(List<Finding> findings) {
        Verdict verdict = Verdict.PASS;
        for (Finding f : findings) {
            verdict = verdict.mergeWith(f.toVerdict());
        }
        return verdict;
    }

    private ScanResult unavailableResult(Duration duration) {
        return new ScanResult(
            "gitleaks",
            Verdict.PASS,
            List.of(),
            duration,
            false,
            "gitleaks not installed"
        );
    }

    private String getStringOrDefault(JsonObject obj, String key, String defaultValue) {
        if (obj.has(key) && !obj.get(key).isJsonNull()) {
            return obj.get(key).getAsString();
        }
        return defaultValue;
    }

    private int getIntOrDefault(JsonObject obj, String key, int defaultValue) {
        if (obj.has(key) && !obj.get(key).isJsonNull()) {
            return obj.get(key).getAsInt();
        }
        return defaultValue;
    }
}
