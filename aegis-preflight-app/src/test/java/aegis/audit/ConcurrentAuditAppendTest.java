package aegis.audit;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Regression for the multi-process chain fork: two AuditStore CONNECTIONS
 * (simulating two Aegis instances) must not read the same chain head and
 * append siblings. BEGIN IMMEDIATE serializes them at the DB level.
 */
class ConcurrentAuditAppendTest {

    @TempDir
    Path tmp;

    @Test
    void twoConnectionsAppendingConcurrentlyDoNotForkChain() throws Exception {
        Path db = tmp.resolve("concurrent.db");

        try (AuditLogger writerA = new AuditLogger(db.toString());
             AuditLogger writerB = new AuditLogger(db.toString())) {

            int perWriter = 40;
            CountDownLatch start = new CountDownLatch(1);
            ExecutorService pool = Executors.newFixedThreadPool(2);

            Runnable taskA = () -> {
                try {
                    start.await();
                    for (int i = 0; i < perWriter; i++) {
                        writerA.logCommandDecision("cmd-A-" + i,
                            aegis.policy.CommandDecision.allow("test"), "S-A");
                    }
                } catch (Exception ignored) {
                }
            };
            Runnable taskB = () -> {
                try {
                    start.await();
                    for (int i = 0; i < perWriter; i++) {
                        writerB.logCommandDecision("cmd-B-" + i,
                            aegis.policy.CommandDecision.block("test"), "S-B");
                    }
                } catch (Exception ignored) {
                }
            };

            pool.submit(taskA);
            pool.submit(taskB);
            start.countDown();
            pool.shutdown();
            assertTrue(pool.awaitTermination(60, TimeUnit.SECONDS),
                "writers finished in time");

            assertEquals(perWriter * 2, writerA.getAuditStore().count(),
                "all interleaved appends persisted");
            AuditStore.ChainVerification verification = writerA.verifyChain();
            assertTrue(verification.valid(),
                "no fork under cross-connection concurrency: " + verification);
        }
    }
}
