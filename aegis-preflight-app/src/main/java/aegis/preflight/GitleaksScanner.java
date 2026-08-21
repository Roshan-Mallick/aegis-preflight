package aegis.preflight;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Wraps Gitleaks as an external host subprocess:
 *
 *   gitleaks detect --no-git --source &lt;workspace&gt; --report-format json --report-path &lt;tmp&gt;
 *
 * Exit codes: 0 = clean, 1 = leaks found, &gt;1 = tool error.
 * Findings are parsed from the real Gitleaks JSON report — never mocked.
 */
public class GitleaksScanner {

    private static final Logger log = LoggerFactory.getLogger(GitleaksScanner.class);
    private static final Gson gson = new Gson();
    private static final long TIMEOUT_SECONDS = 120;

    private final Path workspace;

    public GitleaksScanner(Path workspace) {
        this.workspace = workspace.toAbsolutePath().normalize();
    }

    public ScanResult scan() throws ScannerException {
        Instant start = Instant.now();

        Optional<Path> binary = ExternalToolResolver.findGitleaks();
        if (binary.isEmpty()) {
            log.warn("gitleaks not found on host — secret scan unavailable");
            return unavailable(Duration.between(start, Instant.now()));
        }

        Path report;
        try {
            report = Files.createTempFile("aegis-gitleaks-", ".json");
        } catch (IOException e) {
            throw new ScannerException("Could not create temp report file for gitleaks", e);
        }

        List<String> cmd = List.of(
            binary.get().toString(),
            "detect",
            "--no-git",
            "--source", workspace.toString(),
            "--report-format", "json",
            "--report-path", report.toString(),
            "--no-banner",
            "--redact",
            "--log-level", "error"
        );

        try {
            ExternalToolResolver.ProcessResult result =
                ExternalToolResolver.run(cmd, workspace, TIMEOUT_SECONDS);

            Duration duration = Duration.between(start, Instant.now());

            if (result.exitCode() > 1) {
                throw new ScannerException("gitleaks failed (exit=" + result.exitCode() + "): "
                    + ExternalToolResolver.firstLines(result.stderr(), 5));
            }

            String json = Files.isRegularFile(report) ? Files.readString(report) : "[]";
            List<Finding> findings = parseReport(json);

            // gitleaks exit code 1 means leaks were found; treat 0/1 as valid scans
            Verdict verdict = findings.isEmpty() ? Verdict.PASS : computeVerdict(findings);

            log.info("Gitleaks scan: exit={} findings={} verdict={} ({}ms)",
                result.exitCode(), findings.size(), verdict, duration.toMillis());

            return new ScanResult("gitleaks", verdict, findings, duration, true, json);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ScannerException("gitleaks scan interrupted", e);
        } catch (IOException e) {
            throw new ScannerException("gitleaks could not be executed: " + e.getMessage(), e);
        } finally {
            try {
                Files.deleteIfExists(report);
            } catch (IOException ignored) {
            }
        }
    }

    private List<Finding> parseReport(String json) {
        List<Finding> findings = new ArrayList<>();
        if (json == null || json.isBlank()) {
            return findings;
        }
        try {
            JsonArray results = gson.fromJson(json.strip(), JsonArray.class);
            if (results == null) {
                return findings;
            }
            for (JsonElement elem : results) {
                JsonObject obj = elem.getAsJsonObject();
                findings.add(parseFinding(obj));
            }
        } catch (Exception e) {
            log.warn("Failed to parse gitleaks JSON report: {}", e.getMessage());
        }
        return findings;
    }

    private Finding parseFinding(JsonObject obj) {
        String ruleId = stringOr(obj, "RuleID", "unknown");
        String file = stringOr(obj, "File", "");
        int startLine = intOr(obj, "StartLine", 0);
        String match = stringOr(obj, "Match", "");
        String description = stringOr(obj, "Description", "");

        // gitleaks reports absolute paths when --source is absolute — relativize for the UI
        String relFile = file.startsWith(workspace.toString())
            ? workspace.relativize(Path.of(file)).toString()
            : file;

        Finding.Severity severity = mapSeverity(ruleId);
        String remediation = buildRemediation(ruleId, relFile, startLine, match, description);

        return new Finding(Finding.FindingType.SECRET, severity, "gitleaks", relFile, startLine, remediation);
    }

    /**
     * Template-based explanation generated from the actual finding —
     * deterministic, no LLM involved.
     */
    private String buildRemediation(String ruleId, String file, int line, String match, String gitleaksDescription) {
        String masked = maskSecret(match);
        String lower = ruleId.toLowerCase();

        if (lower.contains("aws")) {
            return "Detected hardcoded AWS access key in " + file + ":" + line
                + " (" + masked + ") — classified " + "CRITICAL"
                + " by Gitleaks rule '" + ruleId + "'. Remove it and rotate the key in IAM immediately.";
        }
        if (lower.contains("private-key")) {
            return "Detected a private key material in " + file + ":" + line
                + " — classified CRITICAL by Gitleaks rule '" + ruleId + "'. "
                + "Remove from source, add to .gitignore and rotate the key.";
        }
        if (lower.contains("generic-api-key") || lower.contains("api")) {
            return "Detected hardcoded API key in " + file + ":" + line
                + " (" + masked + ") — flagged by Gitleaks rule '" + ruleId + "'. "
                + "Move it to an environment variable or a secrets manager.";
        }
        if (lower.contains("token")) {
            return "Detected hardcoded token in " + file + ":" + line
                + " (" + masked + ") — flagged by Gitleaks rule '" + ruleId + "'. "
                + "Revoke the token and load it from the environment instead.";
        }
        String extra = gitleaksDescription == null || gitleaksDescription.isBlank()
            ? ""
            : " (" + gitleaksDescription + ")";
        return "Detected potential secret in " + file + ":" + line
            + " (" + masked + ") — matched by Gitleaks rule '" + ruleId + "'" + extra
            + ". Remove the secret and store it securely.";
    }

    private Finding.Severity mapSeverity(String ruleId) {
        String lower = ruleId.toLowerCase();
        if (lower.contains("aws") || lower.contains("private-key")) {
            return Finding.Severity.CRITICAL;
        }
        if (lower.contains("generic-api-key") || lower.contains("api")
            || lower.contains("password") || lower.contains("slack")) {
            return Finding.Severity.HIGH;
        }
        if (lower.contains("token")) {
            return Finding.Severity.MEDIUM;
        }
        return Finding.Severity.LOW;
    }

    private String maskSecret(String secret) {
        if (secret == null || secret.isBlank()) {
            return "***";
        }
        String s = secret.strip();
        if (s.contains("REDACTED")) {
            return "[redacted by gitleaks]";
        }
        if (s.length() <= 8) {
            return "***";
        }
        return s.substring(0, 4) + "…" + s.substring(s.length() - 4);
    }

    private Verdict computeVerdict(List<Finding> findings) {
        Verdict verdict = Verdict.PASS;
        for (Finding f : findings) {
            verdict = verdict.mergeWith(f.toVerdict());
        }
        return verdict;
    }

    private ScanResult unavailable(Duration duration) {
        return new ScanResult("gitleaks", Verdict.PASS, List.of(), duration, false,
            "gitleaks binary not found on host");
    }

    private static String stringOr(JsonObject obj, String key, String def) {
        return obj.has(key) && !obj.get(key).isJsonNull() ? obj.get(key).getAsString() : def;
    }

    private static int intOr(JsonObject obj, String key, int def) {
        return obj.has(key) && !obj.get(key).isJsonNull() ? obj.get(key).getAsInt() : def;
    }
}
