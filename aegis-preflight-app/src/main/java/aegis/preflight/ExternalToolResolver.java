package aegis.preflight;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

/**
 * Locates external scanner binaries (gitleaks, semgrep, trivy) for the host.
 *
 * Resolution order: the bundled resources directory first (shipped with the
 * installer — no network, no PATH assumption), then known install locations,
 * then PATH lookup via `which`.
 *
 * The bundled resources root is discovered from, in order:
 *   1. system property aegis.resources.dir
 *   2. environment variable AEGIS_RESOURCES_DIR
 *   3. ./resources relative to the working directory (and its parent)
 *   4. /opt/aegis-preflight/resources (deb install layout)
 */
public final class ExternalToolResolver {

    private ExternalToolResolver() {
    }

    /** Root of the bundled offline resources (semgrep-rules/, bin/). */
    public static Path resourceRoot() {
        String prop = System.getProperty("aegis.resources.dir");
        if (prop != null && !prop.isBlank() && Files.isDirectory(Path.of(prop))) {
            return Path.of(prop).toAbsolutePath().normalize();
        }
        String env = System.getenv("AEGIS_RESOURCES_DIR");
        if (env != null && !env.isBlank() && Files.isDirectory(Path.of(env))) {
            return Path.of(env).toAbsolutePath().normalize();
        }
        for (Path base : List.of(Path.of(System.getProperty("user.dir")),
                                 Path.of(System.getProperty("user.dir")).getParent() == null
                                     ? Path.of(System.getProperty("user.dir"))
                                     : Path.of(System.getProperty("user.dir")).getParent())) {
            Path candidate = base.resolve("resources");
            if (Files.isDirectory(candidate.resolve("bin"))
                || Files.isDirectory(candidate.resolve("semgrep-rules"))) {
                return candidate.toAbsolutePath().normalize();
            }
        }
        return Path.of("/opt/aegis-preflight/resources");
    }

    public static Optional<Path> findGitleaks() {
        return find("gitleaks", List.of(
            resourceRoot().resolve("bin").resolve("gitleaks").toString(),
            System.getProperty("user.home") + "/bin/gitleaks",
            "/usr/local/bin/gitleaks",
            "/usr/bin/gitleaks",
            "/opt/homebrew/bin/gitleaks"
        ));
    }

    public static Optional<Path> findTrivy() {
        return find("trivy", List.of(
            resourceRoot().resolve("bin").resolve("trivy").toString(),
            "/usr/local/bin/trivy",
            "/usr/bin/trivy"
        ));
    }

    public static Optional<Path> findSemgrep() {
        return find("semgrep", List.of(
            System.getProperty("user.home") + "/.local/bin/semgrep",
            "/usr/local/bin/semgrep",
            "/usr/bin/semgrep"
        ));
    }

    public static Optional<Path> find(String toolName, List<String> extraCandidates) {
        for (String candidate : extraCandidates) {
            Path p = Path.of(candidate);
            if (Files.isRegularFile(p) && Files.isExecutable(p)) {
                return Optional.of(p);
            }
        }
        try {
            List<String> cmd = List.of("/bin/sh", "-c", "which " + toolName + " 2>/dev/null");
            Process proc = new ProcessBuilder(cmd).start();
            String out;
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(proc.getInputStream()))) {
                out = reader.readLine();
            }
            proc.waitFor(10, TimeUnit.SECONDS);
            if (out != null && !out.isBlank()) {
                Path p = Path.of(out.strip());
                if (Files.isExecutable(p)) {
                    return Optional.of(p);
                }
            }
        } catch (Exception ignored) {
            // fall through
        }
        return Optional.empty();
    }

    /**
     * Runs a host subprocess and captures stdout/stderr without treating
     * non-zero exit as an exception — scanners use exit codes as signals
     * (e.g. gitleaks exits 1 when leaks are found).
     */
    public static ProcessResult run(List<String> command, Path workingDir, long timeoutSeconds)
            throws IOException, InterruptedException {
        ProcessBuilder pb = new ProcessBuilder(command);
        if (workingDir != null) {
            pb.directory(workingDir.toFile());
        }
        pb.redirectErrorStream(false);

        Process process = pb.start();

        StringBuilder stdout = new StringBuilder();
        StringBuilder stderr = new StringBuilder();

        Thread outThread = drain(process.getInputStream(), stdout);
        Thread errThread = drain(process.getErrorStream(), stderr);

        boolean finished = process.waitFor(timeoutSeconds, TimeUnit.SECONDS);
        if (!finished) {
            process.destroyForcibly();
            throw new IOException("Command timed out after " + timeoutSeconds + "s: " + command.get(0));
        }
        outThread.join(5000);
        errThread.join(5000);

        return new ProcessResult(process.exitValue(), stdout.toString(), stderr.toString());
    }

    private static Thread drain(java.io.InputStream is, StringBuilder sink) {
        Thread t = new Thread(() -> {
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(is))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    sink.append(line).append('\n');
                }
            } catch (IOException ignored) {
                // stream closed on destroy
            }
        }, "process-drain");
        t.setDaemon(true);
        t.start();
        return t;
    }

    public record ProcessResult(int exitCode, String stdout, String stderr) {

        public boolean ok() {
            return exitCode == 0;
        }

        public String combinedOutput() {
            return (stdout + (stderr.isBlank() ? "" : "\nSTDERR:\n" + stderr)).strip();
        }
    }

    public static List<String> tail(String s, int maxChars) {
        if (s == null) {
            return List.of();
        }
        String stripped = s.strip();
        if (stripped.length() <= maxChars) {
            return List.of(stripped);
        }
        return List.of("…" + stripped.substring(stripped.length() - maxChars));
    }

    public static String firstLines(String s, int n) {
        if (s == null || s.isBlank()) {
            return "";
        }
        List<String> lines = new ArrayList<>();
        for (String line : s.split("\n")) {
            lines.add(line);
            if (lines.size() >= n) {
                break;
            }
        }
        return String.join("\n", lines);
    }
}
