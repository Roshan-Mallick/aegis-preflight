package aegis.policy;

/**
 * Three-state outcome of a pre-execution {@link CommandGate} evaluation.
 *
 * Each constant carries a reason string describing WHY the decision was made
 * (matched rule, blocked tool, denied path, ...). Reasons are attached at
 * creation time on the evaluating thread via the factories below and must be
 * consumed immediately — do not cache decisions across threads, since enum
 * constants are shared singletons.
 */
public enum CommandDecision {

    /** Policy explicitly allows the command; it may execute immediately. */
    ALLOW,

    /** Policy denies the command; it must never reach docker exec. */
    BLOCK,

    /** Policy cannot auto-approve the command; a human must approve or deny. */
    REQUIRE_APPROVAL;

    private String reason = "";

    public static CommandDecision allow(String reason) {
        return ALLOW.withReason(reason);
    }

    public static CommandDecision block(String reason) {
        return BLOCK.withReason(reason);
    }

    public static CommandDecision requireApproval(String reason) {
        return REQUIRE_APPROVAL.withReason(reason);
    }

    /**
     * Attaches a reason to this decision and returns it for fluent use.
     * Blank/null reasons fall back to a sensible per-state default.
     */
    public CommandDecision withReason(String reason) {
        this.reason = (reason == null || reason.isBlank()) ? defaultReason() : reason;
        return this;
    }

    /** The human-readable explanation for this decision (never null/blank). */
    public String reason() {
        return (reason == null || reason.isBlank()) ? defaultReason() : reason;
    }

    public boolean isAllowed() {
        return this == ALLOW;
    }

    public boolean isBlocked() {
        return this == BLOCK;
    }

    public boolean needsApproval() {
        return this == REQUIRE_APPROVAL;
    }

    /** Short display label for terminal/UI output. */
    public String label() {
        return switch (this) {
            case ALLOW -> "ALLOW";
            case BLOCK -> "BLOCK";
            case REQUIRE_APPROVAL -> "REQUIRE APPROVAL";
        };
    }

    private String defaultReason() {
        return switch (this) {
            case ALLOW -> "allowed by sandbox policy";
            case BLOCK -> "blocked by sandbox policy";
            case REQUIRE_APPROVAL -> "requires manual approval";
        };
    }
}
