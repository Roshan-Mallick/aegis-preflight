package aegis.gui;

/**
 * Standalone launcher that does NOT extend javafx.application.Application.
 *
 * Launching via this class allows JavaFX to run from the shaded fat jar on
 * the plain classpath (java -cp aegis-preflight-1.0.0-all.jar aegis.gui.Launcher)
 * without the "JavaFX runtime components are missing" module check that fires
 * when the main class itself extends Application.
 *
 * This is the entry point used by the packaged desktop bundles (.deb).
 */
public final class Launcher {

    private Launcher() {
    }

    public static void main(String[] args) {
        AegisApp.main(args);
    }
}
