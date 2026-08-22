package aegis.policy;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PolicyEngineDefaultTest {

    /**
     * AC5: loadDefault() must load the bundled classpath resource — no
     * external /policies/ directory on disk.
     */
    @Test
    void bundledResourceLoads() {
        SandboxPolicy policy = assertDoesNotThrow(PolicyEngine::loadDefault);

        assertNotNull(policy);
        assertEquals("1.0.0", policy.getVersion());
        assertNotNull(policy.getTools());
        assertNotNull(policy.getNetwork());
        assertNotNull(policy.getFilesystem());
        assertNotNull(policy.getResources());
        assertTrue(policy.getTools().getAllowed().contains("ls"));
        assertTrue(policy.getTools().getBlocked().contains("curl"));
    }

    @Test
    void engineBuiltFromBundledPolicyEvaluatesHostsAndTools() throws PolicyException {
        PolicyEngine engine = new PolicyEngine(PolicyEngine.loadDefault());
        assertFalse(engine.isToolAllowed("curl"));
        assertTrue(engine.isToolAllowed("git"));
        assertFalse(engine.isHostAllowed("evil.example.com"));
    }
}
