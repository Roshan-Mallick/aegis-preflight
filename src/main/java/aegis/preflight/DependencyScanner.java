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

public class DependencyScanner {

    private static final Logger log = LoggerFactory.getLogger(DependencyScanner.class);
    private static final Gson gson = new Gson();

    private enum ProjectType {
        PYTHON,
        NODE,
        NONE
    }

    private final DockerSandbox sandbox;

    public DependencyScanner(DockerSandbox sandbox) {
        this.sandbox = sandbox;
    }

    public ScanResult scan() throws ScannerException {
        Instant start = Instant.now();
        log.info("Dependency scan starting");

        ProjectType projectType = detectProjectType();
        if (projectType == ProjectType.NONE) {
            log.info("No Python or Node.js project detected, skipping dependency scan");
            return noProjectResult(Duration.between(start, Instant.now()));
        }

        ScanResult result = switch (projectType) {
            case PYTHON -> scanPython();
            case NODE -> scanNode();
            default -> noProjectResult(Duration.between(start, Instant.now()));
        };

        log.info("Dependency scan complete: {} ({} findings, verdict={})",
            projectType, result.findingCount(), result.getVerdict());
        return result;
    }

    public ScanResult scanPython() throws ScannerException {
        Instant start = Instant.now();

        if (!isToolInstalled("pip-audit")) {
            return unavailableResult("pip-audit", Duration.between(start, Instant.now()));
        }

        String cmd = "pip-audit --format=json --desc 2>/dev/null || pip-audit --format=json 2>/dev/null";
        String output;
        try {
            output = sandbox.execInContainer(cmd);
        } catch (SandboxException e) {
            throw new ScannerException("pip-audit execution failed: " + e.getMessage(), e);
        }

        Duration duration = Duration.between(start, Instant.now());
        List<Finding> findings = parsePipAuditOutput(output);
        Verdict verdict = computeVerdict(findings);

        return new ScanResult("pip-audit", verdict, findings, duration, true, output);
    }

    public ScanResult scanNode() throws ScannerException {
        Instant start = Instant.now();

        String auditCmd = "cd /workspace && npm audit --json 2>/dev/null";
        String output;
        try {
            output = sandbox.execInContainer(auditCmd);
        } catch (SandboxException e) {
            throw new ScannerException("npm audit execution failed: " + e.getMessage(), e);
        }

        Duration duration = Duration.between(start, Instant.now());
        List<Finding> findings = parseNpmAuditOutput(output);
        Verdict verdict = computeVerdict(findings);

        return new ScanResult("npm-audit", verdict, findings, duration, true, output);
    }

    private ProjectType detectProjectType() {
        boolean hasPython = false;
        boolean hasNode = false;

        try {
            String pyCheck = sandbox.execInContainer(
                "ls /workspace/requirements.txt /workspace/setup.py /workspace/pyproject.toml 2>/dev/null"
            );
            hasPython = pyCheck.strip().contains("/");
        } catch (SandboxException e) {
            // ignore
        }

        try {
            String nodeCheck = sandbox.execInContainer(
                "ls /workspace/package.json 2>/dev/null"
            );
            hasNode = nodeCheck.strip().contains("package.json");
        } catch (SandboxException e) {
            // ignore
        }

        if (hasPython && hasNode) {
            return ProjectType.PYTHON;
        }
        if (hasPython) {
            return ProjectType.PYTHON;
        }
        if (hasNode) {
            return ProjectType.NODE;
        }
        return ProjectType.NONE;
    }

    private List<Finding> parsePipAuditOutput(String json) {
        List<Finding> findings = new ArrayList<>();
        if (json == null || json.isBlank()) {
            return findings;
        }

        try {
            JsonObject root = gson.fromJson(json, JsonObject.class);
            if (root == null || !root.has("dependencies")) {
                return findings;
            }

            JsonArray deps = root.getAsJsonArray("dependencies");
            for (JsonElement elem : deps) {
                JsonObject dep = elem.getAsJsonObject();
                String name = getStringOrDefault(dep, "name", "unknown");
                String version = getStringOrDefault(dep, "version", "unknown");

                if (!dep.has("vulns")) {
                    continue;
                }

                JsonArray vulns = dep.getAsJsonArray("vulns");
                for (JsonElement vulnElem : vulns) {
                    JsonObject vuln = vulnElem.getAsJsonObject();
                    findings.add(parsePipVulnerability(name, version, vuln));
                }
            }
        } catch (Exception e) {
            log.warn("Failed to parse pip-audit JSON: {}", e.getMessage());
        }

        return findings;
    }

    private Finding parsePipVulnerability(String packageName, String version, JsonObject vuln) {
        String vulnId = getStringOrDefault(vuln, "id", "unknown");
        String description = getStringOrDefault(vuln, "description", "Vulnerability in " + packageName);

        String fixVersions = "unknown";
        if (vuln.has("fix_versions") && vuln.get("fix_versions").isJsonArray()) {
            JsonArray fixes = vuln.getAsJsonArray("fix_versions");
            if (fixes.size() > 0) {
                fixVersions = fixes.get(0).getAsString();
            }
        }

        Finding.Severity severity = mapCveSeverity(description);
        String remediation = buildPipRemediation(packageName, version, fixVersions, vulnId);

        return new Finding(
            Finding.FindingType.VULN,
            severity,
            "requirements.txt",
            0,
            remediation
        );
    }

    private String buildPipRemediation(String packageName, String installedVersion,
                                        String fixVersion, String vulnId) {
        if (!"unknown".equals(fixVersion)) {
            return "Update " + packageName + " from " + installedVersion
                + " to " + fixVersion + ". Run: pip install --upgrade " + packageName + ">=" + fixVersion;
        }
        return "Vulnerability " + vulnId + " found in " + packageName + "@" + installedVersion
            + ". No fixed version available yet. Review " + packageName + " for alternatives or "
            + "apply upstream patches.";
    }

    private List<Finding> parseNpmAuditOutput(String json) {
        List<Finding> findings = new ArrayList<>();
        if (json == null || json.isBlank()) {
            return findings;
        }

        try {
            JsonObject root = gson.fromJson(json, JsonObject.class);
            if (root == null) {
                return findings;
            }

            if (root.has("vulnerabilities")) {
                JsonObject vulns = root.getAsJsonObject("vulnerabilities");
                for (String packageName : vulns.keySet()) {
                    JsonObject vulnData = vulns.getAsJsonObject(packageName);
                    findings.addAll(parseNpmVulnerability(packageName, vulnData));
                }
            } else if (root.has("advisories")) {
                JsonObject advisories = root.getAsJsonObject("advisories");
                for (String id : advisories.keySet()) {
                    JsonObject adv = advisories.getAsJsonObject(id);
                    findings.add(parseNpmAdvisory(adv));
                }
            }
        } catch (Exception e) {
            log.warn("Failed to parse npm audit JSON: {}", e.getMessage());
        }

        return findings;
    }

    private List<Finding> parseNpmVulnerability(String packageName, JsonObject vulnData) {
        List<Finding> findings = new ArrayList<>();

        String severity = getStringOrDefault(vulnData, "severity", "info");
        String title = getStringOrDefault(vulnData, "title", "Vulnerability in " + packageName);
        String range = getStringOrDefault(vulnData, "range", "unknown");

        Finding.Severity mapped = mapNpmSeverity(severity);
        String remediation = buildNpmRemediation(packageName, range, title);

        findings.add(new Finding(
            Finding.FindingType.DEPENDENCY,
            mapped,
            "package.json",
            0,
            remediation
        ));

        return findings;
    }

    private Finding parseNpmAdvisory(JsonObject adv) {
        String module = getStringOrDefault(adv, "module_name", "unknown");
        String title = getStringOrDefault(adv, "title", "Vulnerability");
        String severity = getStringOrDefault(adv, "severity", "info");
        String patchedVersions = getStringOrDefault(adv, "patched_versions", "unknown");

        Finding.Severity mapped = mapNpmSeverity(severity);
        String remediation = buildNpmAdvisoryRemediation(module, patchedVersions, title);

        return new Finding(
            Finding.FindingType.DEPENDENCY,
            mapped,
            "package.json",
            0,
            remediation
        );
    }

    private String buildNpmRemediation(String packageName, String range, String title) {
        return "Update " + packageName + " to a version outside the vulnerable range "
            + "(" + range + "). Run: npm install " + packageName + "@latest. "
            + "Advisory: " + title;
    }

    private String buildNpmAdvisoryRemediation(String packageName, String patchedVersions,
                                                String title) {
        if (!"unknown".equals(patchedVersions)) {
            return "Update " + packageName + " to " + patchedVersions + " or later. "
                + "Run: npm install " + packageName + "@latest. Advisory: " + title;
        }
        return "Vulnerability in " + packageName + ": " + title
            + ". No patched version available. Review for alternatives.";
    }

    private Finding.Severity mapNpmSeverity(String severity) {
        return switch (severity.toLowerCase()) {
            case "critical" -> Finding.Severity.CRITICAL;
            case "high" -> Finding.Severity.HIGH;
            case "moderate" -> Finding.Severity.MEDIUM;
            case "low" -> Finding.Severity.LOW;
            default -> Finding.Severity.INFO;
        };
    }

    private Finding.Severity mapCveSeverity(String description) {
        String lower = description.toLowerCase();
        if (lower.contains("remote code execution") || lower.contains("sql injection")) {
            return Finding.Severity.CRITICAL;
        }
        if (lower.contains("cross-site scripting") || lower.contains("path traversal")) {
            return Finding.Severity.HIGH;
        }
        if (lower.contains("denial of service") || lower.contains("information disclosure")) {
            return Finding.Severity.MEDIUM;
        }
        return Finding.Severity.LOW;
    }

    private Verdict computeVerdict(List<Finding> findings) {
        Verdict verdict = Verdict.PASS;
        for (Finding f : findings) {
            verdict = verdict.mergeWith(f.toVerdict());
        }
        return verdict;
    }

    private boolean isToolInstalled(String tool) {
        try {
            String output = sandbox.execInContainer("which " + tool + " 2>/dev/null");
            return output.strip().contains(tool);
        } catch (SandboxException e) {
            return false;
        }
    }

    private ScanResult unavailableResult(String scannerName, Duration duration) {
        return new ScanResult(
            scannerName,
            Verdict.PASS,
            List.of(),
            duration,
            false,
            scannerName + " not installed"
        );
    }

    private ScanResult noProjectResult(Duration duration) {
        return new ScanResult(
            "dependency-scan",
            Verdict.PASS,
            List.of(),
            duration,
            true,
            "no Python/Node project detected"
        );
    }

    private String getStringOrDefault(JsonObject obj, String key, String defaultValue) {
        if (obj.has(key) && !obj.get(key).isJsonNull()) {
            return obj.get(key).getAsString();
        }
        return defaultValue;
    }
}
