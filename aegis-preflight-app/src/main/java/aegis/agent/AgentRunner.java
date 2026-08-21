package aegis.agent;

import aegis.sandbox.DockerSandbox;
import aegis.sandbox.SandboxException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class AgentRunner {

    private static final Logger log = LoggerFactory.getLogger(AgentRunner.class);

    private final DockerSandbox sandbox;

    public AgentRunner(DockerSandbox sandbox) {
        if (sandbox == null) {
            throw new IllegalArgumentException("Sandbox must not be null");
        }
        this.sandbox = sandbox;
    }

    public RunResult run(String agentCommand, long timeoutSeconds) throws AgentException {
        log.info("Agent run starting: {}", agentCommand);

        Instant start = Instant.now();
        Map<Path, FileSnapshot> before = snapshotFiles();
        log.info("Before snapshot: {} files", before.size());

        String output;
        int exitCode;
        RunStatus status;

        try {
            String wrappedCmd = agentCommand
                + " 2>&1; echo \"__AEGIS_EXIT__:$?\"";
            output = sandbox.execInContainer(wrappedCmd);

            exitCode = parseExitCode(output);
            output = stripExitMarker(output);
            status = exitCode == 0 ? RunStatus.SUCCESS : RunStatus.AGENT_ERROR;

            log.info("Agent exited with code: {}", exitCode);

        } catch (SandboxException e) {
            output = e.getMessage();
            exitCode = -1;
            status = RunStatus.CONTAINER_ERROR;
            log.error("Container error during agent run: {}", e.getMessage());
        }

        Map<Path, FileSnapshot> after = snapshotFiles();
        log.info("After snapshot: {} files", after.size());

        List<FileChange> diff = diffSnapshots(before, after);

        Instant end = Instant.now();
        Duration duration = Duration.between(start, end);

        List<FileChange> added = diff.stream()
            .filter(c -> c.getType() == FileChange.ChangeType.ADDED)
            .toList();
        List<FileChange> modified = diff.stream()
            .filter(c -> c.getType() == FileChange.ChangeType.MODIFIED)
            .toList();
        List<FileChange> deleted = diff.stream()
            .filter(c -> c.getType() == FileChange.ChangeType.DELETED)
            .toList();
        List<FileSnapshot> unchanged = new ArrayList<>();

        for (Map.Entry<Path, FileSnapshot> entry : after.entrySet()) {
            boolean isModified = modified.stream()
                .anyMatch(c -> Path.of(c.getRelativePath()).equals(entry.getKey()));
            boolean isAdded = added.stream()
                .anyMatch(c -> Path.of(c.getRelativePath()).equals(entry.getKey()));
            if (!isModified && !isAdded) {
                unchanged.add(entry.getValue());
            }
        }

        RunResult result = new RunResult(
            status, output, exitCode, duration,
            added, modified, deleted, unchanged
        );

        log.info("Agent run complete: {}", result.summary());
        return result;
    }

    public RunResult run(String agentCommand) throws AgentException {
        return run(agentCommand, 300);
    }

    public Map<Path, FileSnapshot> snapshotFiles() throws AgentException {
        String hashCmd = "find /workspace -type f -exec sha256sum {} + 2>/dev/null "
            + "| sed 's|/workspace/||'";

        try {
            String output = sandbox.execInContainer(hashCmd);
            return FileSnapshot.fromHashOutput(output);
        } catch (SandboxException e) {
            throw new AgentException("Failed to snapshot files: " + e.getMessage(), e);
        }
    }

    public List<FileChange> diffSnapshots(Map<Path, FileSnapshot> before,
                                          Map<Path, FileSnapshot> after) {
        List<FileChange> changes = new ArrayList<>();

        for (Map.Entry<Path, FileSnapshot> entry : after.entrySet()) {
            Path path = entry.getKey();
            FileSnapshot afterSnap = entry.getValue();
            FileSnapshot beforeSnap = before.get(path);

            if (beforeSnap == null) {
                changes.add(new FileChange(
                    FileChange.ChangeType.ADDED,
                    path.toString(),
                    null,
                    afterSnap.getSha256()
                ));
            } else if (!beforeSnap.getSha256().equals(afterSnap.getSha256())) {
                changes.add(new FileChange(
                    FileChange.ChangeType.MODIFIED,
                    path.toString(),
                    beforeSnap.getSha256(),
                    afterSnap.getSha256()
                ));
            }
        }

        for (Map.Entry<Path, FileSnapshot> entry : before.entrySet()) {
            if (!after.containsKey(entry.getKey())) {
                changes.add(new FileChange(
                    FileChange.ChangeType.DELETED,
                    entry.getKey().toString(),
                    entry.getValue().getSha256(),
                    null
                ));
            }
        }

        changes.sort((a, b) -> {
            int typeCmp = a.getType().compareTo(b.getType());
            if (typeCmp != 0) return typeCmp;
            return a.getRelativePath().compareTo(b.getRelativePath());
        });

        return changes;
    }

    private int parseExitCode(String output) {
        if (output == null) {
            return -1;
        }
        String marker = "__AEGIS_EXIT__:";
        int idx = output.lastIndexOf(marker);
        if (idx < 0) {
            return -1;
        }
        try {
            String codeStr = output.substring(idx + marker.length()).strip();
            return Integer.parseInt(codeStr);
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    private String stripExitMarker(String output) {
        if (output == null) {
            return "";
        }
        String marker = "__AEGIS_EXIT__:";
        int idx = output.lastIndexOf(marker);
        if (idx >= 0) {
            int prevNewline = output.lastIndexOf("\n", idx);
            if (prevNewline >= 0) {
                return output.substring(0, prevNewline);
            }
            return "";
        }
        return output;
    }
}
