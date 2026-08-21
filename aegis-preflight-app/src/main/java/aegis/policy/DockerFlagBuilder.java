package aegis.policy;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class DockerFlagBuilder {

    private final List<String> flags = new ArrayList<>();

    public DockerFlagBuilder applyResources(ResourcePolicy resources) {
        if (resources == null) {
            return this;
        }

        flags.add("--memory=" + resources.getMemory());
        flags.add("--cpus=" + resources.getCpus());
        flags.add("--tmpfs=/tmp:size=" + resources.getTmpfsSize());

        if (resources.getPidsLimit() > 0) {
            flags.add("--pids-limit=" + resources.getPidsLimit());
        }

        if (resources.getUlimits() != null) {
            for (Map.Entry<String, Integer> entry : resources.getUlimits().entrySet()) {
                flags.add("--ulimit=" + entry.getKey() + "=" + entry.getValue());
            }
        }

        return this;
    }

    public DockerFlagBuilder applyFilesystem(FilesystemPolicy fs, String hostWorkspace) {
        if (fs == null) {
            return this;
        }

        flags.add("--read-only");

        String containerWorkspace = "/workspace";
        flags.add("-v");
        flags.add(hostWorkspace + ":" + containerWorkspace);

        if (fs.getWritePaths() != null) {
            for (String path : fs.getWritePaths()) {
                String mountPath = "/workspace/" + path.replaceFirst("/$", "");
                flags.add("--tmpfs");
                flags.add(mountPath + ":rw,size=128m");
            }
        }

        return this;
    }

    public DockerFlagBuilder applyNetwork(aegis.policy.NetworkPolicyConfig netConfig) {
        if (netConfig == null) {
            flags.add("--network=none");
            return this;
        }

        switch (netConfig.getMode()) {
            case "none":
                flags.add("--network=none");
                break;
            case "host":
                flags.add("--network=host");
                break;
            case "restricted":
            default:
                flags.add("--network=none");
                break;
        }

        return this;
    }

    public DockerFlagBuilder addExtra(String... extraFlags) {
        for (String flag : extraFlags) {
            flags.add(flag);
        }
        return this;
    }

    public List<String> build() {
        return List.copyOf(flags);
    }

    public String buildSummary() {
        StringBuilder sb = new StringBuilder();
        for (String flag : flags) {
            sb.append(flag).append(" ");
        }
        return sb.toString().trim();
    }
}
