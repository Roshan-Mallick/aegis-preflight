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
 * Wraps Trivy as an external host subprocess — fully offline:
 *
 *   trivy fs --skip-db-update --offline-scan --scanners vuln
 *            --format json --exit-code 0 &lt;workspace&gt;
 *
 * The vulnerability DB is pre-downloaded during one-time setup
 * (~/.cache/trivy/db); --skip-db-update + --offline-scan guarantee zero
 * network access at scan time. Replaces pip-audit and npm audit entirely:
 * a single tool covers requirements.txt, pyproject.toml, package.json and
 * lockfiles.
 *
 * Findings are parsed from Results[].Vulnerabilities[] into the unified
 * Finding model — never mocked. Exit code 0 is enforced via --exit-code 0 so
 * any non-zero exit is a real tool error, not a "vulnerabilities found" signal.
 */
public class TrivyScanner {

    private static final Logger log = LoggerFactory.getLogger(TrivyScanner.class);
    private static final Gson gson = new Gson();
    private static final long TIMEOUT_SECONDS = 300;

    private final Path workspace;

    public TrivyScanner(Path workspace) {
        this.workspace = workspace.toAbsolutePath().normalize();
    }

    public ScanResult scan() throws ScannerException {
        Instant start = Instant.now();

        Optional<Path> binary = ExternalToolResolver.findTrivy();
        if (binary.isEmpty()) {
            log.warn("trivy not found — dependency vulnerability scan unavailable");
            return unavailable(Duration.between(start, Instant.now()));
        }

        List<String> cmd = List.of(
            binary.get().toString(),
            "fs",
            "--skip-db-update",
            "--offline-scan",
            "--scanners", "vuln",
            "--format", "json",
            "--exit-code", "0",
            "--quiet",
            workspace.toString()
        );

        try {
            ExternalToolResolver.ProcessResult result =
                ExternalToolResolver.run(cmd, workspace, TIMEOUT_SECONDS);

            Duration duration = Duration.between(start, Instant.now());

            if (result.exitCode() != 0) {
                throw new ScannerException("trivy failed (exit=" + result.exitCode() + "): "
                    + ExternalToolResolver.firstLines(result.stderr(), 5));
            }

            List<Finding> findings = parseReport(result.stdout());
            Verdict verdict = findings.isEmpty() ? Verdict.PASS : computeVerdict(findings);

            log.info("Trivy scan: exit={} findings={} verdict={} ({}ms)",
                result.exitCode(), findings.size(), verdict, duration.toMillis());

            return new ScanResult("trivy", verdict, findings, duration, true, result.stdout());

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ScannerException("trivy scan interrupted", e);
        } catch (IOException e) {
            throw new ScannerException("trivy could not be executed: " + e.getMessage(), e);
        }
    }

    // --- parser over REAL trivy JSON output ---

    private List<Finding> parseReport(String json) {
        List<Finding> findings = new ArrayList<>();
        if (json == null || json.isBlank()) {
            return findings;
        }
        try {
            JsonObject root = gson.fromJson(json.strip(), JsonObject.class);
            if (root == null || !root.has("Results") || root.getAsJsonArray("Results").isJsonNull()) {
                return findings;
            }
            JsonArray results = root.getAsJsonArray("Results");
            for (JsonElement rElem : results) {
                JsonObject result = rElem.getAsJsonObject();
                String target = stringOr(result, "Target", "unknown");

                if (!result.has("Vulnerabilities") || result.get("Vulnerabilities").isJsonNull()) {
                    continue;
                }
                for (JsonElement vElem : result.getAsJsonArray("Vulnerabilities")) {
                    JsonObject vuln = vElem.getAsJsonObject();
                    findings.add(vulnToFinding(target, vuln));
                }
            }
        } catch (Exception e) {
            log.warn("Failed to parse trivy JSON report: {}", e.getMessage());
        }
        return findings;
    }

    private Finding vulnToFinding(String target, JsonObject vuln) {
        String cveId = stringOr(vuln, "VulnerabilityID", "CVE-unknown");
        String title = stringOr(vuln, "Title", "");
        String pkg = stringOr(vuln, "PkgName", "unknown");
        String installed = stringOr(vuln, "InstalledVersion", "unknown");
        String fixed = stringOr(vuln, "FixedVersion", "");
        String primaryUrl = stringOr(vuln, "PrimaryURL", "");

        Finding.Severity severity = mapSeverity(stringOr(vuln, "Severity", "UNKNOWN"));
        String remediation = "Vulnerability " + cveId + " in " + pkg + "@" + installed
            + (title.isBlank() ? "" : " — " + title)
            + " — classified " + severity + " by Trivy."
            + (fixed.isBlank()
                ? " No fixed version published yet; pin an alternative or apply upstream patches."
                : " Upgrade to " + pkg + ">=" + fixed + ".")
            + (primaryUrl.isBlank() ? "" : " Ref: " + primaryUrl);

        return new Finding(Finding.FindingType.CVE, severity, "trivy", target, 0, remediation);
    }

    private Finding.Severity mapSeverity(String s) {
        return switch (s == null ? "UNKNOWN" : s.toUpperCase()) {
            case "CRITICAL" -> Finding.Severity.CRITICAL;
            case "HIGH" -> Finding.Severity.HIGH;
            case "MEDIUM" -> Finding.Severity.MEDIUM;
            case "LOW" -> Finding.Severity.LOW;
            default -> Finding.Severity.HIGH; // unknown-severity published CVEs gate releases conservatively
        };
    }

    private Verdict computeVerdict(List<Finding> findings) {
        Verdict verdict = Verdict.PASS;
        for (Finding f : findings) {
            verdict = verdict.mergeWith(f.toVerdict());
        }
        return verdict;
    }

    private ScanResult unavailable(Duration duration) {
        return new ScanResult("trivy", Verdict.PASS, List.of(), duration, false,
            "trivy binary not found (expected bundled in resources/bin/trivy)");
    }

    private static String stringOr(JsonObject obj, String key, String def) {
        return obj.has(key) && !obj.get(key).isJsonNull() ? obj.get(key).getAsString() : def;
    }
}
