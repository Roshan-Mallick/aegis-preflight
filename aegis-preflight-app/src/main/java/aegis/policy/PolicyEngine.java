package aegis.policy;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public class PolicyEngine {

    private static final Logger log = LoggerFactory.getLogger(PolicyEngine.class);
    private static final Gson gson = new GsonBuilder().setPrettyPrinting().create();

    private final SandboxPolicy policy;

    public PolicyEngine(SandboxPolicy policy) {
        if (policy == null) {
            throw new IllegalArgumentException("Policy must not be null");
        }
        this.policy = policy;
        log.info("PolicyEngine loaded: v{} — {}", policy.getVersion(), policy.getDescription());
    }

    public static SandboxPolicy loadFromFile(Path policyFile) throws PolicyException {
        if (!Files.exists(policyFile)) {
            throw new PolicyException("Policy file not found: " + policyFile);
        }
        try (Reader reader = Files.newBufferedReader(policyFile)) {
            SandboxPolicy policy = gson.fromJson(reader, SandboxPolicy.class);
            validate(policy);
            return policy;
        } catch (IOException e) {
            throw new PolicyException("Failed to read policy file: " + e.getMessage(), e);
        }
    }

    public static SandboxPolicy loadFromJson(String json) throws PolicyException {
        SandboxPolicy policy = gson.fromJson(json, SandboxPolicy.class);
        validate(policy);
        return policy;
    }

    public static final String DEFAULT_POLICY_RESOURCE = "/policies/default-sandbox-policy.json";

    /**
     * Loads the bundled default policy packaged inside the app resources —
     * zero external filesystem dependency, matching the self-contained
     * packaging direction. (The previous /policies/... absolute path never
     * existed on disk.)
     */
    public static SandboxPolicy loadDefault() throws PolicyException {
        InputStream in = PolicyEngine.class.getResourceAsStream(DEFAULT_POLICY_RESOURCE);
        if (in == null) {
            throw new PolicyException("Bundled default policy not found on classpath: "
                + DEFAULT_POLICY_RESOURCE);
        }
        try (Reader reader = new InputStreamReader(in, StandardCharsets.UTF_8)) {
            SandboxPolicy policy = gson.fromJson(reader, SandboxPolicy.class);
            validate(policy);
            return policy;
        } catch (IOException e) {
            throw new PolicyException("Failed to read bundled default policy: " + e.getMessage(), e);
        }
    }

    public DockerFlagBuilder buildDockerFlags(String hostWorkspace) {
        DockerFlagBuilder builder = new DockerFlagBuilder();

        builder.applyNetwork(policy.getNetwork());
        builder.applyFilesystem(policy.getFilesystem(), hostWorkspace);
        builder.applyResources(policy.getResources());

        builder.addExtra(
            "-w", "/workspace",
            "ubuntu:22.04",
            "sleep", "infinity"
        );

        log.debug("Docker flags: {}", builder.buildSummary());
        return builder;
    }

    public boolean isToolAllowed(String toolName) {
        ToolPolicy tools = policy.getTools();
        if (tools == null) {
            return true;
        }

        if (tools.getBlocked() != null) {
            for (String blocked : tools.getBlocked()) {
                if (blocked.equalsIgnoreCase(toolName)) {
                    return false;
                }
            }
        }

        if (tools.getAllowed() != null && !tools.getAllowed().isEmpty()) {
            return tools.getAllowed().stream()
                .anyMatch(a -> a.equalsIgnoreCase(toolName));
        }

        return true;
    }

    public boolean isToolBlocked(String toolName) {
        return !isToolAllowed(toolName);
    }

    public boolean isHostAllowed(String hostname) {
        NetworkPolicyConfig net = policy.getNetwork();
        if (net == null) {
            return false;
        }

        if ("none".equals(net.getMode())) {
            return false;
        }

        if (net.getAllowedHosts() != null) {
            for (String allowed : net.getAllowedHosts()) {
                if (hostname.equals(allowed) || hostname.endsWith("." + allowed)) {
                    return true;
                }
            }
        }

        return false;
    }

    public List<String> getAllowedTools() {
        ToolPolicy tools = policy.getTools();
        if (tools == null || tools.getAllowed() == null) {
            return List.of();
        }
        return tools.getAllowed();
    }

    public List<String> getBlockedTools() {
        ToolPolicy tools = policy.getTools();
        if (tools == null || tools.getBlocked() == null) {
            return List.of();
        }
        return tools.getBlocked();
    }

    public List<String> getAllowedHosts() {
        NetworkPolicyConfig net = policy.getNetwork();
        if (net == null || net.getAllowedHosts() == null) {
            return List.of();
        }
        return net.getAllowedHosts();
    }

    public SandboxPolicy getPolicy() {
        return policy;
    }

    private static void validate(SandboxPolicy policy) throws PolicyException {
        if (policy == null) {
            throw new PolicyException("Policy JSON parsed to null");
        }
        if (policy.getFilesystem() == null) {
            throw new PolicyException("Policy missing required section: filesystem");
        }
        if (policy.getNetwork() == null) {
            throw new PolicyException("Policy missing required section: network");
        }
        if (policy.getTools() == null) {
            throw new PolicyException("Policy missing required section: tools");
        }
        if (policy.getResources() == null) {
            throw new PolicyException("Policy missing required section: resources");
        }
    }
}
