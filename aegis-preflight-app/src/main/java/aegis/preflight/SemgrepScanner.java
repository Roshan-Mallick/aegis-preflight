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
import java.util.stream.Stream;

/**
 * Wraps Semgrep as an external host subprocess — fully offline:
 *
 *   semgrep --json --quiet --no-git-ignore
 *           --config=&lt;resources&gt;/semgrep-rules/python
 *           --config=&lt;resources&gt;/semgrep-rules/javascript
 *           &lt;workspace&gt;
 *
 * Rules are the bundled semgrep-rules snapshot shipped with the app
 * (resources/semgrep-rules, pinned upstream commit recorded in
 * resources/semgrep-rules.version). NEVER --config=auto or --config=p/...
 * — those fetch rules from the semgrep registry over the network.
 *
 * Language rule sets are only passed when matching source files exist in the
 * workspace. Exit codes: 0 = no findings, 1 = findings found, &gt;1 = error.
 */
public class SemgrepScanner {

    private static final Logger log = LoggerFactory.getLogger(SemgrepScanner.class);
    private static final Gson gson = new Gson();
    private static final long TIMEOUT_SECONDS = 300;

    private final Path workspace;

    public SemgrepScanner(Path workspace) {
        this.workspace = workspace.toAbsolutePath().normalize();
    }

    public ScanResult scan() throws ScannerException {
        Instant start = Instant.now();

        Optional<Path> binary = ExternalToolResolver.findSemgrep();
        if (binary.isEmpty()) {
            log.warn("semgrep not found — SAST scan unavailable");
            return unavailable(Duration.between(start, Instant.now()));
        }

        List<String> configs = new ArrayList<>();
        boolean hasPython = hasMatchingFiles("py");
        boolean hasJs = hasMatchingFiles("js", "jsx", "ts", "tsx", "mjs", "cjs");

        if (hasPython) {
            configs.addAll(List.of("--config", rulePath("python")));
        }
        if (hasJs) {
            configs.addAll(List.of("--config", rulePath("javascript")));
        }

        if (configs.isEmpty()) {
            return new ScanResult("semgrep", Verdict.PASS, List.of(),
                Duration.between(start, Instant.now()), true,
                "no python/javascript sources in workspace — SAST skipped");
        }

        List<String> cmd = new ArrayList<>();
        cmd.add(binary.get().toString());
        cmd.add("--json");
        cmd.add("--quiet");
        // A security gate must never inherit ignore rules from whatever repo
        // happens to enclose the workspace (e.g. CI checkouts where the
        // scanned dir is git-ignored) — always scan every target file.
        cmd.add("--no-git-ignore");
        // Zero telemetry: semgrep would otherwise POST usage metrics to
        // semgrep.dev. Bundled rules only, no registry, no metrics.
        cmd.add("--metrics=off");
        cmd.addAll(configs);
        cmd.add(workspace.toString());

        try {
            ExternalToolResolver.ProcessResult result =
                ExternalToolResolver.run(cmd, workspace, TIMEOUT_SECONDS);

            Duration duration = Duration.between(start, Instant.now());

            if (result.exitCode() > 1) {
                throw new ScannerException("semgrep failed (exit=" + result.exitCode() + "): "
                    + ExternalToolResolver.firstLines(result.stderr(), 5));
            }

            List<Finding> findings = parseReport(result.stdout());
            Verdict verdict = findings.isEmpty() ? Verdict.PASS : computeVerdict(findings);

            log.info("Semgrep scan: exit={} findings={} verdict={} ({}ms)",
                result.exitCode(), findings.size(), verdict, duration.toMillis());

            return new ScanResult("semgrep", verdict, findings, duration, true, result.stdout());

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ScannerException("semgrep scan interrupted", e);
        } catch (IOException e) {
            throw new ScannerException("semgrep could not be executed: " + e.getMessage(), e);
        }
    }

    private String rulePath(String language) {
        return ExternalToolResolver.resourceRoot()
            .resolve("semgrep-rules")
            .resolve(language)
            .toString();
    }

    private boolean hasMatchingFiles(String... extensions) {
        try (Stream<Path> files = Files.walk(workspace)) {
            return files.filter(Files::isRegularFile).anyMatch(p -> {
                if (isIgnored(p)) {
                    return false;
                }
                String name = p.getFileName().toString().toLowerCase();
                for (String ext : extensions) {
                    if (name.endsWith("." + ext)) {
                        return true;
                    }
                }
                return false;
            });
        } catch (IOException e) {
            log.warn("Could not enumerate workspace for {}: {}", workspace, e.getMessage());
            return false;
        }
    }

    private boolean isIgnored(Path p) {
        String s = p.toString();
        return s.contains("/.git/") || s.contains("/node_modules/") || s.contains("/target/")
            || s.contains("/.idea/") || s.contains("/__pycache__/") || s.contains("/.gradle/")
            || s.contains("/resources/semgrep-rules/");
    }

    // --- parser over REAL semgrep JSON output ---

    private List<Finding> parseReport(String json) {
        List<Finding> findings = new ArrayList<>();
        if (json == null || json.isBlank()) {
            return findings;
        }
        try {
            JsonObject root = gson.fromJson(json.strip(), JsonObject.class);
            if (root == null || !root.has("results") || root.getAsJsonArray("results").isJsonNull()) {
                return findings;
            }
            for (JsonElement elem : root.getAsJsonArray("results")) {
                JsonObject obj = elem.getAsJsonObject();
                findings.add(parseFinding(obj));
            }
        } catch (Exception e) {
            log.warn("Failed to parse semgrep JSON report: {}", e.getMessage());
        }
        return findings;
    }

    private Finding parseFinding(JsonObject obj) {
        String checkId = stringOr(obj, "check_id", "unknown");
        // semgrep prefixes rule IDs with the config path it was given
        // (…/resources/semgrep-rules.python.lang.security.foo) — strip the
        // filesystem noise so the UI shows the canonical rule ID.
        int prefixIdx = checkId.indexOf(".semgrep-rules.");
        if (prefixIdx >= 0) {
            checkId = checkId.substring(prefixIdx + ".semgrep-rules.".length());
        }
        String path = stringOr(obj, "path", "");
        int line = 0;
        if (obj.has("start") && obj.getAsJsonObject("start").has("line")) {
            line = obj.getAsJsonObject("start").get("line").getAsInt();
        }
        String message = "";
        String severityRaw = "INFO";
        if (obj.has("extra") && obj.getAsJsonObject("extra").isJsonObject()) {
            JsonObject extra = obj.getAsJsonObject("extra");
            message = stringOr(extra, "message", "");
            severityRaw = stringOr(extra, "severity", "INFO");
        }

        String relFile = path.startsWith(workspace.toString())
            ? workspace.relativize(Path.of(path)).toString()
            : path;

        Finding.Severity severity = mapSeverity(severityRaw);
        String description = "SAST rule '" + checkId + "' matched at " + relFile + ":" + line
            + " (" + severity + " by Semgrep). " + message
            + " Review and fix before release.";

        return new Finding(Finding.FindingType.SAST, severity, "semgrep", relFile, line, description);
    }

    /** semgrep severities: ERROR / WARNING / INFO (INVENTORY is treated as INFO). */
    private Finding.Severity mapSeverity(String s) {
        return switch (s == null ? "INFO" : s.toUpperCase()) {
            case "ERROR" -> Finding.Severity.HIGH;
            case "WARNING" -> Finding.Severity.MEDIUM;
            default -> Finding.Severity.LOW;
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
        return new ScanResult("semgrep", Verdict.PASS, List.of(), duration, false,
            "semgrep binary not found on host (pip install semgrep during setup)");
    }

    private static String stringOr(JsonObject obj, String key, String def) {
        return obj.has(key) && !obj.get(key).isJsonNull() ? obj.get(key).getAsString() : def;
    }
}
