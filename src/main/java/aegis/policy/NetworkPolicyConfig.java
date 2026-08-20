package aegis.policy;

import java.util.List;

public class NetworkPolicyConfig {

    private String mode;
    private List<String> allowedHosts;
    private List<String> blockedHosts;
    private boolean allowLocalhost;

    public String getMode() {
        return mode;
    }

    public void setMode(String mode) {
        this.mode = mode;
    }

    public List<String> getAllowedHosts() {
        return allowedHosts;
    }

    public void setAllowedHosts(List<String> allowedHosts) {
        this.allowedHosts = allowedHosts;
    }

    public List<String> getBlockedHosts() {
        return blockedHosts;
    }

    public void setBlockedHosts(List<String> blockedHosts) {
        this.blockedHosts = blockedHosts;
    }

    public boolean isAllowLocalhost() {
        return allowLocalhost;
    }

    public void setAllowLocalhost(boolean allowLocalhost) {
        this.allowLocalhost = allowLocalhost;
    }
}
