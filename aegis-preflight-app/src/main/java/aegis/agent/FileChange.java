package aegis.agent;

public class FileChange {

    public enum ChangeType {
        ADDED,
        MODIFIED,
        DELETED
    }

    private final ChangeType type;
    private final String relativePath;
    private final String hashBefore;
    private final String hashAfter;

    public FileChange(ChangeType type, String relativePath,
                      String hashBefore, String hashAfter) {
        this.type = type;
        this.relativePath = relativePath;
        this.hashBefore = hashBefore;
        this.hashAfter = hashAfter;
    }

    public ChangeType getType() {
        return type;
    }

    public String getRelativePath() {
        return relativePath;
    }

    public String getHashBefore() {
        return hashBefore;
    }

    public String getHashAfter() {
        return hashAfter;
    }

    @Override
    public String toString() {
        return switch (type) {
            case ADDED -> "[+] " + relativePath;
            case MODIFIED -> "[~] " + relativePath;
            case DELETED -> "[-] " + relativePath;
        };
    }
}
