package aegis.policy;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Pre-execution command gate — the first real command-level policy enforcement.
 *
 * Every command typed into the guarded terminal is evaluated here BEFORE it is
 * allowed to reach {@code docker exec}. Evaluation order (explicit deny always
 * wins):
 *
 *   1. blocked tools        (ToolPolicy.blocked, whole-word scan)  -> BLOCK
 *   2. blocked patterns     (ToolPolicy.blockedPatterns globs)     -> BLOCK
 *   3. denied paths         (FilesystemPolicy.denied globs)        -> BLOCK
 *   4. allow-list membership (ToolPolicy.allowed)                  -> ALLOW,
 *      anything unlisted under a non-empty allow-list               -> REQUIRE_APPROVAL
 *
 * A blank/empty allow-list means permissive mode: unlisted tools are allowed.
 */
public class CommandGate {

    private final ToolPolicy tools;
    private final FilesystemPolicy filesystem;

    public CommandGate(SandboxPolicy policy) {
        this(policy == null ? null : policy.getTools(),
             policy == null ? null : policy.getFilesystem());
    }

    public CommandGate(ToolPolicy tools, FilesystemPolicy filesystem) {
        this.tools = tools;
        this.filesystem = filesystem;
    }

    /** Gate backed by the bundled default policy resource. */
    public static CommandGate loadDefault() throws PolicyException {
        return new CommandGate(PolicyEngine.loadDefault());
    }

    /**
     * Evaluates a raw shell command string against the sandbox policy.
     * Never throws for bad input — unparsable commands are held for approval
     * rather than silently executed.
     */
    public CommandDecision evaluate(String command) {
        if (command == null || command.isBlank()) {
            return CommandDecision.block("empty command");
        }

        List<String> tokens = tokenize(command);
        if (tokens.isEmpty()) {
            return CommandDecision.block("empty command");
        }

        String primaryTool = primaryTool(tokens);

        // 1. Explicitly blocked tools — check the primary tool AND every other
        //    word in the command so `sudo curl`, `xargs wget` etc. are caught.
        for (String blocked : blockedTools()) {
            for (String token : tokens) {
                if (token.equalsIgnoreCase(blocked)) {
                    return CommandDecision.block("tool not allowed: " + blocked);
                }
            }
            if (primaryTool.equalsIgnoreCase(blocked)) {
                return CommandDecision.block("tool not allowed: " + blocked);
            }
        }

        // 2. Blocked shell patterns ("curl * | sh", "chmod 777 *", ...).
        for (String pattern : blockedPatterns()) {
            if (globMatches(pattern, command)) {
                return CommandDecision.block("matches denied pattern: " + pattern);
            }
        }

        // 3. Denied filesystem globs (.env, *.pem, .ssh/, **/secrets, ...).
        //    The command itself is checked too, so redirections like
        //    "echo x > .env" are caught by their trailing token.
        for (String token : tokens) {
            String deniedBy = deniedPathGlob(token);
            if (deniedBy != null) {
                return CommandDecision.block("touches protected path: " + deniedBy);
            }
        }

        // 4. Allow-list membership of the primary tool.
        List<String> allowed = allowedTools();
        if (allowed.isEmpty()) {
            return CommandDecision.allow("permissive mode (no allow-list configured)");
        }
        boolean member = allowed.stream().anyMatch(a -> a.equalsIgnoreCase(primaryTool));
        if (member) {
            return CommandDecision.allow("tool approved by policy: " + primaryTool);
        }
        return CommandDecision.requireApproval(
            "tool not on allow-list: " + primaryTool + " — needs human review");
    }

    /* ------------------------------ helpers ------------------------------ */

    /**
     * First meaningful token with any path prefix stripped ("/usr/bin/rm" ->
     * "rm") and any leading environment assignments skipped ("FOO=bar curl"
     * -> "curl").
     */
    private String primaryTool(List<String> tokens) {
        for (String token : tokens) {
            if (token.contains("=") && !token.startsWith("/")
                    && token.matches("[A-Za-z_][A-Za-z0-9_]*=.*")) {
                continue;
            }
            int slash = token.lastIndexOf('/');
            return slash >= 0 ? token.substring(slash + 1) : token;
        }
        return tokens.get(0);
    }

    /**
     * Whitespace tokenizer that strips surrounding quotes and keeps words
     * intact. Not a full POSIX shell parser — enough fidelity for policy
     * matching without executing anything.
     */
    private static List<String> tokenize(String command) {
        List<String> tokens = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        char quote = 0;
        for (int i = 0; i < command.length(); i++) {
            char c = command.charAt(i);
            if (quote != 0) {
                if (c == quote) {
                    quote = 0;
                } else {
                    current.append(c);
                }
            } else if (c == '"' || c == '\'') {
                quote = c;
            } else if (Character.isWhitespace(c)) {
                if (!current.isEmpty()) {
                    tokens.add(current.toString());
                    current.setLength(0);
                }
            } else {
                current.append(c);
            }
        }
        if (!current.isEmpty()) {
            tokens.add(current.toString());
        }
        return tokens;
    }

    /**
     * Returns the denied glob that matches the given token, or null.
     * Handles three glob shapes:
     *   "*.pem"  — matches basename or whole path
     *   ".ssh/"  — directory: true when it appears as any path component
     *   double-star-prefixed multi-segment globs — leading wildcard prefix is
     *   ignored, so e.g. "secrets" matches as a component anywhere in the path
     */
    private String deniedPathGlob(String token) {
        if (filesystem == null || filesystem.getDenied() == null || token.isEmpty()) {
            return null;
        }
        String clean = stripQuotes(token);
        String bare = clean.startsWith("./") ? clean.substring(2) : clean;
        String base = bare.contains("/") ? bare.substring(bare.lastIndexOf('/') + 1) : bare;

        for (String glob : filesystem.getDenied()) {
            if (glob == null || glob.isBlank()) {
                continue;
            }
            if (glob.endsWith("/")) {
                String dir = glob.substring(0, glob.length() - 1);
                if (isPathComponent(bare, dir)) {
                    return glob;
                }
                continue;
            }
            String g = glob.startsWith("**/") ? glob.substring(3) : glob;
            if (globMatches(g, base) || globMatches(g, bare)) {
                return glob;
            }
        }
        return null;
    }

    private static boolean isPathComponent(String path, String component) {
        if (path.equals(component)) {
            return true;
        }
        return path.contains("/" + component + "/")
            || path.startsWith(component + "/")
            || path.endsWith("/" + component);
    }

    /** Case-sensitive glob match supporting *, ** and ?. */
    static boolean globMatches(String glob, String value) {
        if (glob == null || value == null) {
            return false;
        }
        return Pattern.compile(globToRegex(glob)).matcher(value).matches();
    }

    private static String globToRegex(String glob) {
        StringBuilder sb = new StringBuilder("^");
        for (int i = 0; i < glob.length(); i++) {
            char c = glob.charAt(i);
            switch (c) {
                case '*' -> {
                    if (i + 1 < glob.length() && glob.charAt(i + 1) == '*') {
                        sb.append(".*");
                        i++;
                    } else {
                        sb.append("[^ ]*");
                    }
                }
                case '?' -> sb.append('.');
                default -> {
                    if ("\\.[]{}()+-^$|".indexOf(c) >= 0) {
                        sb.append('\\');
                    }
                    sb.append(c);
                }
            }
        }
        return sb.append('$').toString();
    }

    private static String stripQuotes(String s) {
        if (s.length() >= 2 && ((s.startsWith("\"") && s.endsWith("\""))
                || (s.startsWith("'") && s.endsWith("'")))) {
            return s.substring(1, s.length() - 1);
        }
        return s;
    }

    private List<String> allowedTools() {
        return tools == null || tools.getAllowed() == null ? List.of() : tools.getAllowed();
    }

    private List<String> blockedTools() {
        return tools == null || tools.getBlocked() == null ? List.of() : tools.getBlocked();
    }

    private List<String> blockedPatterns() {
        return tools == null || tools.getBlockedPatterns() == null
            ? List.of()
            : tools.getBlockedPatterns();
    }
}
