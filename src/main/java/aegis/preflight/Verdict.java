package aegis.preflight;

public enum Verdict {

    PASS("No security issues found. Code is safe to release."),

    WARNING("Security advisory found. Review recommended before release."),

    BLOCK("Security issue found. Code must be fixed before release.");

    private final String description;

    Verdict(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }

    public boolean requiresAction() {
        return this == BLOCK;
    }

    public Verdict mergeWith(Verdict other) {
        if (this == BLOCK || other == BLOCK) {
            return BLOCK;
        }
        if (this == WARNING || other == WARNING) {
            return WARNING;
        }
        return PASS;
    }
}
