package aegis.monitor;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Rule-based runtime observer for the sandboxed agent (no ML / no LLM).
 *
 * Sources:
 *   1. `docker events` stream filtered to the sandbox container — process
 *      execs, container lifecycle, network attach/detach.
 *   2. Structured markers the agent writes to stdout:
 *         [AEGIS-EVENT] {"kind":"file_access","detail":"..."}
 *      which map 1:1 to file_access / process_exec / network_attempt events.
 *
 * Flagging rules (deterministic):
 *   - R-NET-ANY   : any network attempt while sandbox policy is none
 *   - R-FS-OUTSIDE: filesystem access targeting a path outside /workspace
 *   - R-SECRET    : known secret patterns in event details
 */
public class ActivityMonitor implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(ActivityMonitor.class);

    /** Known secret patterns (subset of gitleaks-style rules for live flagging). */
    private static final List<Pattern> SECRET_PATTERNS = List.of(
        Pattern.compile("AKIA[0-9A-Z]{16}"),
        Pattern.compile("(?i)aws.{0,20}(secret|access).{0,5}key"),
        Pattern.compile("sk-(live|test|proj)-[0-9a-zA-Z]{16,}"),
        Pattern.compile("-----BEGIN [A-Z ]*PRIVATE KEY-----"),
        Pattern.compile("gh[pousr]_[0-9a-zA-Z]{30,}"),
        Pattern.compile("(?i)(api[_-]?key|passwd|password)\\s*[=:]\\s*['\"][^'\"]{6,}")
    );

    private static final Pattern OUTSIDE_WORKSPACE = Pattern.compile(
        "^(/(etc|root|home|var|usr|opt|bin|sbin|lib|boot|dev|proc|sys)(/.*)?)$");

    private static final Pattern AGENT_MARKER =
        Pattern.compile("^\\[?AEGIS-EVENT\\]?\\s*(\\{.*})\\s*$");

    private static final Gson gson = new Gson();

    private final String containerName;
    private final Consumer<ActivityEvent> listener;
    private final Consumer<ActivityEvent> flaggedSink;   // e.g. audit logger
    private final boolean networkAllowed;

    private Process dockerEventsProcess;
    private volatile boolean running;
    private final List<ActivityEvent> history = new ArrayList<>();
    private final Object historyLock = new Object();

    public ActivityMonitor(String containerName, boolean networkAllowed,
                           Consumer<ActivityEvent> listener,
                           Consumer<ActivityEvent> flaggedSink) {
        this.containerName = containerName;
        this.networkAllowed = networkAllowed;
        this.listener = listener == null ? e -> { } : listener;
        this.flaggedSink = flaggedSink == null ? e -> { } : flaggedSink;
    }

    public void start() {
        if (running) {
            return;
        }
        running = true;

        Thread t = new Thread(this::tailDockerEvents, "activity-monitor");
        t.setDaemon(true);
        t.start();
        log.info("ActivityMonitor started for container {}", containerName);
    }

    private void tailDockerEvents() {
        List<String> cmd = List.of(
            "docker", "events",
            "--filter", "container=" + containerName,
            "--format", "{{json .}}"
        );
        try {
            dockerEventsProcess = new ProcessBuilder(cmd).start();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                    dockerEventsProcess.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while (running && (line = reader.readLine()) != null) {
                    handleDockerEventLine(line);
                }
            }
        } catch (IOException e) {
            if (running) {
                log.warn("docker events stream ended: {}", e.getMessage());
            }
        } finally {
            record(ActivityEvent.of(ActivityEvent.Kind.CONTAINER_EVENT, "monitor stopped"));
        }
    }

    private void handleDockerEventLine(String line) {
        try {
            JsonObject obj = gson.fromJson(line, JsonObject.class);
            if (obj == null) {
                return;
            }
            String action = obj.has("Action") ? obj.get("Action").getAsString() : "";
            String actorCommand = "";
            if (obj.has("Actor") && obj.get("Actor").isJsonObject()) {
                JsonObject actor = obj.getAsJsonObject("Actor");
                if (actor.has("Attributes") && actor.get("Attributes").isJsonObject()) {
                    JsonObject attrs = actor.getAsJsonObject("Attributes");
                    if (attrs.has("command")) {
                        actorCommand = attrs.get("command").getAsString();
                    }
                }
            }

            if (action.startsWith("exec_create:")) {
                String command = action.substring("exec_create:".length()).strip();
                ingestProcessExec(command.isEmpty() ? actorCommand : command);
            } else if (action.startsWith("exec_start:")) {
                // exec_create already captured the command line
            } else if (action.contains("network_attach") || action.contains("network_connect")) {
                ActivityEvent ev = ActivityEvent.of(ActivityEvent.Kind.NETWORK_ATTEMPT,
                    "container attached a network interface");
                record(networkAllowed ? ev : ev.flagged("R-NET-ATTACH"));
            } else if (!action.isBlank()) {
                record(ActivityEvent.of(ActivityEvent.Kind.CONTAINER_EVENT, "docker: " + action));
            }
        } catch (Exception e) {
            log.debug("Unparseable docker event line: {}", line);
        }
    }

    /**
     * Feeds raw stdout/stderr of an agent exec through the rule engine.
     * Recognizes [AEGIS-EVENT] JSON markers and plain output lines.
     */
    public void ingestAgentOutput(String output) {
        if (output == null || output.isBlank()) {
            return;
        }
        for (String line : output.split("\n")) {
            String trimmed = line.strip();
            if (trimmed.isEmpty()) {
                continue;
            }
            Matcher m = AGENT_MARKER.matcher(trimmed);
            if (m.matches()) {
                parseAgentMarker(m.group(1));
            }
        }
    }

    private void parseAgentMarker(String json) {
        try {
            JsonObject obj = gson.fromJson(json, JsonObject.class);
            if (obj == null || !obj.has("kind") || !obj.has("detail")) {
                return;
            }
            String kindStr = obj.get("kind").getAsString().toLowerCase();
            String detail = obj.get("detail").getAsString();

            ActivityEvent.Kind kind = switch (kindStr) {
                case "file_access" -> ActivityEvent.Kind.FILE_ACCESS;
                case "process_exec" -> ActivityEvent.Kind.PROCESS_EXEC;
                case "network_attempt" -> ActivityEvent.Kind.NETWORK_ATTEMPT;
                default -> null;
            };
            if (kind == null) {
                return;
            }
            record(applyRules(kind, detail));
        } catch (Exception e) {
            log.debug("Bad agent marker: {}", json);
        }
    }

    public void ingestFileAccess(String detail) {
        record(applyRules(ActivityEvent.Kind.FILE_ACCESS, detail));
    }

    public void ingestNetworkAttempt(String detail) {
        record(applyRules(ActivityEvent.Kind.NETWORK_ATTEMPT, detail));
    }

    public void ingestProcessExec(String command) {
        record(applyRules(ActivityEvent.Kind.PROCESS_EXEC, command));
    }

    /**
     * Deterministic rule engine — flags secrets, out-of-workspace access and
     * any networking under a no-network policy.
     */
    public ActivityEvent applyRules(ActivityEvent.Kind kind, String detail) {
        ActivityEvent ev = ActivityEvent.of(kind, detail);

        if (kind == ActivityEvent.Kind.NETWORK_ATTEMPT && !networkAllowed) {
            return ev.flagged("R-NET-ANY");
        }
        if (kind == ActivityEvent.Kind.FILE_ACCESS) {
            Matcher m = OUTSIDE_WORKSPACE.matcher(extractPath(detail));
            if (m.matches()) {
                return ev.flagged("R-FS-OUTSIDE");
            }
        }
        for (Pattern p : SECRET_PATTERNS) {
            Matcher m = p.matcher(detail);
            if (m.find()) {
                return ev.flagged("R-SECRET:" + p.pattern());
            }
        }
        return ev;
    }

    /**
     * Extracts the filesystem path from an event detail. Details come either
     * as "<verb> <path>" ("write /root/pwned") or a bare absolute path —
     * return the first whitespace-delimited token that starts with '/'.
     */
    private String extractPath(String detail) {
        for (String token : detail.strip().split("\\s+")) {
            if (token.startsWith("/")) {
                return token;
            }
        }
        return detail.strip();
    }

    private void record(ActivityEvent ev) {
        synchronized (historyLock) {
            history.add(ev);
            if (history.size() > 2000) {
                history.remove(0);
            }
        }
        listener.accept(ev);
        if (ev.flagged()) {
            flaggedSink.accept(ev);
        }
    }

    public List<ActivityEvent> snapshotHistory() {
        synchronized (historyLock) {
            return new ArrayList<>(history);
        }
    }

    public long flaggedCount() {
        synchronized (historyLock) {
            return history.stream().filter(ActivityEvent::flagged).count();
        }
    }

    public boolean isRunning() {
        return running;
    }

    @Override
    public void close() {
        running = false;
        if (dockerEventsProcess != null) {
            dockerEventsProcess.destroyForcibly();
        }
        log.info("ActivityMonitor stopped");
    }
}
