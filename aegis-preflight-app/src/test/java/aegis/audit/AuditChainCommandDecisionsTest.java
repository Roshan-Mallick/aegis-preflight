package aegis.audit;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Hash-chain integrity across the new guarded-terminal event types: command
 * decisions (ALLOW/BLOCK/REQUIRE_APPROVAL), approvals and denials must chain
 * and the full chain must still verify.
 */
class AuditChainCommandDecisionsTest {

    @TempDir
    Path tmp;

    private AuditLogger newLogger() throws AuditException {
        return new AuditLogger(tmp.resolve("audit-" + System.nanoTime() + ".db").toString());
    }

    @Test
    void commandDecisionsAndApprovalsChainAndVerify() throws Exception {
        try (AuditLogger audit = newLogger()) {
            aegis.policy.CommandDecision block =
                aegis.policy.CommandDecision.block("tool not allowed: curl");
            aegis.policy.CommandDecision hold =
                aegis.policy.CommandDecision.requireApproval("tool not on allow-list");

            audit.logSandboxStart("aegis-sandbox-test", "/tmp/ws", "NONE");
            audit.logCommandDecision("ls -la", aegis.policy.CommandDecision.allow(
                "tool approved by policy: ls"), "S-1");
            audit.logCommandDecision("curl http://example.com", block, "S-1");
            audit.logCommandDecision("bash -c 'echo hi'", hold, "S-2");
            audit.logApprovalGranted("bash -c 'echo hi'", "tester");
            audit.logApprovalDenied("uname -a", "tester", "Denied from card");
            audit.logAgentRun("bash -c 'echo hi'", 0, 0, 0, 42);

            List<AuditEvent> events = audit.getRecentEvents(Integer.MAX_VALUE);
            assertTrue(events.stream().anyMatch(e -> e.eventType()
                == AuditEvent.EventType.COMMAND_ALLOWED));
            assertTrue(events.stream().anyMatch(e -> e.eventType()
                == AuditEvent.EventType.TOOL_BLOCKED));
            assertTrue(events.stream().anyMatch(e -> e.eventType()
                == AuditEvent.EventType.APPROVAL_REQUESTED));
            assertTrue(events.stream().anyMatch(e -> e.eventType()
                == AuditEvent.EventType.APPROVAL_GRANTED));
            assertTrue(events.stream().anyMatch(e -> e.eventType()
                == AuditEvent.EventType.DEVELOPER_OVERRIDE));

            AuditStore.ChainVerification verification = audit.verifyChain();
            assertTrue(verification.valid(), verification.toString());
        }
    }

    @Test
    void tamperingWithChainIsStillDetected() throws Exception {
        // Write events, close, mutate a row out-of-band, reopen -> tampered.
        Path db = tmp.resolve("tamper.db");
        try (AuditLogger audit = new AuditLogger(db.toString())) {
            audit.logCommandDecision("curl http://example.com",
                aegis.policy.CommandDecision.block("tool not allowed: curl"), "S-1");
        }
        try (java.sql.Connection c = java.sql.DriverManager
                .getConnection("jdbc:sqlite:" + db)) {
            c.createStatement().executeUpdate(
                "UPDATE audit_events SET payload_json='{}' WHERE id=1");
        }
        try (AuditLogger audit = new AuditLogger(db.toString())) {
            assertFalse(audit.verifyChain().valid());
        }
    }
}
