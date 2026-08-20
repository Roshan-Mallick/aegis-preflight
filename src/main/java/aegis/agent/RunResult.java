package aegis.agent;

import java.nio.file.Path;
import java.time.Duration;
import java.util.List;

public class RunResult {

    private final RunStatus status;
    private final String agentOutput;
    private final int exitCode;
    private final Duration duration;
    private final List<FileChange> added;
    private final List<FileChange> modified;
    private final List<FileChange> deleted;
    private final List<FileSnapshot> unchanged;

    public RunResult(RunStatus status, String agentOutput, int exitCode,
                     Duration duration, List<FileChange> added,
                     List<FileChange> modified, List<FileChange> deleted,
                     List<FileSnapshot> unchanged) {
        this.status = status;
        this.agentOutput = agentOutput;
        this.exitCode = exitCode;
        this.duration = duration;
        this.added = added;
        this.modified = modified;
        this.deleted = deleted;
        this.unchanged = unchanged;
    }

    public RunStatus getStatus() {
        return status;
    }

    public String getAgentOutput() {
        return agentOutput;
    }

    public int getExitCode() {
        return exitCode;
    }

    public Duration getDuration() {
        return duration;
    }

    public List<FileChange> getAdded() {
        return added;
    }

    public List<FileChange> getModified() {
        return modified;
    }

    public List<FileChange> getDeleted() {
        return deleted;
    }

    public List<FileSnapshot> getUnchanged() {
        return unchanged;
    }

    public int totalChanges() {
        return added.size() + modified.size() + deleted.size();
    }

    public boolean hasChanges() {
        return totalChanges() > 0;
    }

    public boolean isBlocked() {
        return status == RunStatus.TIMEOUT
            || status == RunStatus.AGENT_ERROR
            || status == RunStatus.CONTAINER_ERROR;
    }

    public String summary() {
        return String.format(
            "Status: %s | Exit: %d | Duration: %dms | Added: %d | Modified: %d | Deleted: %d | Unchanged: %d",
            status, exitCode, duration.toMillis(),
            added.size(), modified.size(), deleted.size(), unchanged.size()
        );
    }
}
