package aegis.audit;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Canonical hashing for the tamper-evident audit chain.
 *
 * Chain formula (per Aegis spec):
 *   curr_hash = SHA256(prev_hash + timestamp + event_type + payload_json)
 *
 * The first row of the chain uses GENESIS_HASH as its prev_hash.
 * This is a local hash chain for tamper-evidence — not a distributed ledger.
 */
public final class HashChain {

    public static final String GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000";

    private HashChain() {
    }

    public static String computeHash(String prevHash, String timestamp, String eventType, String payloadJson) {
        String canonical = nvl(prevHash) + nvl(timestamp) + nvl(eventType) + nvl(payloadJson);
        return sha256Hex(canonical);
    }

    public static String sha256Hex(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(hash.length * 2);
            for (byte b : hash) {
                sb.append(Character.forDigit((b >> 4) & 0xF, 16));
                sb.append(Character.forDigit(b & 0xF, 16));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available in this JVM", e);
        }
    }

    private static String nvl(String s) {
        return s == null ? "" : s;
    }
}
