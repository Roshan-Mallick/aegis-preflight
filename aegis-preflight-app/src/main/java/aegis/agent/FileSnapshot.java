package aegis.agent;

import java.nio.file.Path;
import java.util.Map;

public class FileSnapshot {

    private final Path relativePath;
    private final String sha256;
    private final long sizeBytes;

    public FileSnapshot(Path relativePath, String sha256, long sizeBytes) {
        this.relativePath = relativePath;
        this.sha256 = sha256;
        this.sizeBytes = sizeBytes;
    }

    public Path getRelativePath() {
        return relativePath;
    }

    public String getSha256() {
        return sha256;
    }

    public long getSizeBytes() {
        return sizeBytes;
    }

    public static Map<Path, FileSnapshot> fromHashOutput(String hashOutput) {
        Map<Path, FileSnapshot> snapshot = new java.util.HashMap<>();
        if (hashOutput == null || hashOutput.isBlank()) {
            return snapshot;
        }
        for (String line : hashOutput.split("\n")) {
            line = line.strip();
            if (line.isEmpty() || !line.contains("  ")) {
                continue;
            }
            int separator = line.indexOf("  ");
            if (separator <= 0 || separator + 2 >= line.length()) {
                continue;
            }
            String hash = line.substring(0, separator);
            String filePath = line.substring(separator + 2).strip();
            snapshot.put(Path.of(filePath), new FileSnapshot(Path.of(filePath), hash, 0));
        }
        return snapshot;
    }

    @Override
    public String toString() {
        return sha256.substring(0, 12) + "  " + relativePath;
    }
}
