package aegis.policy;

import java.util.List;

public class FilesystemPolicy {

    private String workspace;
    private List<String> writePaths;
    private List<String> readOnlyPaths;
    private List<String> denied;

    public String getWorkspace() {
        return workspace;
    }

    public void setWorkspace(String workspace) {
        this.workspace = workspace;
    }

    public List<String> getWritePaths() {
        return writePaths;
    }

    public void setWritePaths(List<String> writePaths) {
        this.writePaths = writePaths;
    }

    public List<String> getReadOnlyPaths() {
        return readOnlyPaths;
    }

    public void setReadOnlyPaths(List<String> readOnlyPaths) {
        this.readOnlyPaths = readOnlyPaths;
    }

    public List<String> getDenied() {
        return denied;
    }

    public void setDenied(List<String> denied) {
        this.denied = denied;
    }
}
