package aegis.sandbox;

public enum NetworkPolicy {

    NONE("--network=none", "No network access at all"),

    RESTRICTED(null, "User-defined network with approved destinations only"),

    FULL("--network=host", "Full host network access (development only)");

    private final String dockerFlag;
    private final String description;

    NetworkPolicy(String dockerFlag, String description) {
        this.dockerFlag = dockerFlag;
        this.description = description;
    }

    public String getDockerFlag() {
        return dockerFlag;
    }

    public String getDescription() {
        return description;
    }

    public boolean isBlocked() {
        return this == NONE;
    }
}
