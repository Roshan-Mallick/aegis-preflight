package aegis.session;

import aegis.audit.AuditEvent;
import aegis.audit.AuditException;
import aegis.audit.AuditLogger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** Approval queue semantics: hold, approve, deny, audit rows, UI snapshot. */
class ApprovalServiceTest {

    @TempDir
    Path tmp;

    private record Captured(AuditLogger logger) implements AutoCloseable {
        @Override
        public void close() throws AuditException {
            logger.close();
        }
    }

    @Test
    void submitHoldsThenApproveExecutesViaCallback() throws Exception {
        try (Captured c = new Captured(newLogger())) {
            List<ApprovalService.PendingRequest> executed = new java.util.ArrayList<>();
            List<ApprovalService.PendingRequest> denied = new java.util.ArrayList<>();
            List<List<ApprovalService.PendingRequest>> uiSnapshots = new java.util.ArrayList<>();

            ApprovalService svc = new ApprovalService(c.logger(),
                executed::add, denied::add, uiSnapshots::add);

            String id = svc.submit("S-1", "bash -c 'echo hi'", "not on allow-list");
            assertTrue(id.startsWith("APR-"));
            assertEquals(1, svc.snapshot().size());
            assertEquals(0, executed.size());

            // While pending: nothing executed.
            Thread.sleep(100);
            assertEquals(0, executed.size());

            assertTrue(svc.approve(id, "tester"));
            assertFalse(svc.snapshot().stream()
                .anyMatch(r -> r.id().equals(id)), "removed from queue after approve");
            assertEquals(1, executed.size());
            assertEquals("bash -c 'echo hi'", executed.get(0).command());
            assertTrue(auditHas(c.logger(), AuditEvent.EventType.APPROVAL_GRANTED));
        }
    }

    @Test
    void denyNeverExecutesAndAuditsOverride() throws Exception {
        try (Captured c = new Captured(newLogger())) {
            List<ApprovalService.PendingRequest> executed = new java.util.ArrayList<>();
            ApprovalService svc = new ApprovalService(c.logger(), executed::add,
                r -> { }, l -> { });

            String id = svc.submit("S-1", "uname -a", "not on allow-list");
            assertTrue(svc.deny(id, "tester", "no reason needed"));
            assertFalse(svc.approve(id, "tester"), "double-resolve is a no-op");
            Thread.sleep(100);
            assertEquals(0, executed.size(), "denied command must never execute");
            assertTrue(auditHas(c.logger(), AuditEvent.EventType.DEVELOPER_OVERRIDE));
        }
    }

    @Test
    void uiListenerReceivesSnapshotOnEveryChange() throws Exception {
        try (Captured c = new Captured(newLogger())) {
            List<Integer> sizes = new java.util.ArrayList<>();
            ApprovalService svc = new ApprovalService(c.logger(),
                r -> { }, r -> { }, l -> sizes.add(l.size()));

            String a = svc.submit("S-1", "cmd-a", "r");
            String b = svc.submit("S-1", "cmd-b", "r");
            svc.approve(a, "u");
            svc.deny(b, "u", "x");
            // notify fires after each mutation: +a -> [a], +b -> [a,b],
            // -a -> [b], -b -> []
            assertEquals(List.of(1, 2, 1, 0), sizes);
        }
    }

    private static boolean auditHas(AuditLogger logger, AuditEvent.EventType type)
            throws AuditException {
        return logger.getRecentEvents(Integer.MAX_VALUE).stream()
            .anyMatch(e -> e.eventType() == type);
    }

    private AuditLogger newLogger() throws AuditException {
        return new AuditLogger(tmp.resolve("approval-" + System.nanoTime() + ".db").toString());
    }
}
