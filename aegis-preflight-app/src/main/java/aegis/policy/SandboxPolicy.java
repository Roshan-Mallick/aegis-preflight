package aegis.policy;

public class SandboxPolicy {

    private String version;
    private String description;
    private FilesystemPolicy filesystem;
    private NetworkPolicyConfig network;
    private ToolPolicy tools;
    private ResourcePolicy resources;

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public FilesystemPolicy getFilesystem() {
        return filesystem;
    }

    public void setFilesystem(FilesystemPolicy filesystem) {
        this.filesystem = filesystem;
    }

    public NetworkPolicyConfig getNetwork() {
        return network;
    }

    public void setNetwork(NetworkPolicyConfig network) {
        this.network = network;
    }

    public ToolPolicy getTools() {
        return tools;
    }

    public void setTools(ToolPolicy tools) {
        this.tools = tools;
    }

    public ResourcePolicy getResources() {
        return resources;
    }

    public void setResources(ResourcePolicy resources) {
        this.resources = resources;
    }
}
