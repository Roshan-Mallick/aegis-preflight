package aegis.gui;

import aegis.ai.OllamaClient;
import aegis.ai.OllamaManager;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.scene.Scene;
import javafx.scene.image.Image;
import javafx.stage.Stage;

import java.util.Objects;

public class AegisApp extends Application {

    private static final String APP_TITLE = "Aegis PreFlight \u2014 Security for AI Coding";
    private static final int MIN_WIDTH = 1200;
    private static final int MIN_HEIGHT = 720;
    /** Single source of truth for the on-device model (verified via `ollama list`). */
    private static final String DEFAULT_MODEL = aegis.ai.LocalSecurityLLM.MODEL;

    private OllamaManager ollamaManager;
    private OllamaClient ollamaClient;

    @Override
    public void start(Stage primaryStage) {
        long appStart = System.currentTimeMillis();

        Image icon = new Image(Objects.requireNonNull(
            getClass().getResourceAsStream("/styles/applogo.png")));
        primaryStage.getIcons().add(icon);

        ollamaManager = new OllamaManager();
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("[Aegis] Shutdown hook: stopping Ollama...");
            ollamaManager.stop();
        }));

        Thread ollamaThread = new Thread(() -> {
            try {
                long start = System.currentTimeMillis();
                ollamaManager.start();
                ollamaManager.ensureModelReady(DEFAULT_MODEL);
                ollamaClient = new OllamaClient(DEFAULT_MODEL);
                // Pre-load model weights so the first Security Report fits its
                // 5-second timeout budget (cold loads take ~10-20s).
                aegis.ai.LocalSecurityLLM.warmup();
                long elapsed = System.currentTimeMillis() - start;
                System.out.println("[Aegis] Ollama ready in " + elapsed + "ms (model: " + DEFAULT_MODEL + ")");
            } catch (Exception e) {
                System.err.println("[Aegis] Ollama startup failed: " + e.getMessage());
                System.err.println("[Aegis] AI features will be unavailable. "
                    + "To fix, run: ollama pull " + DEFAULT_MODEL);
                ollamaClient = null;
            }
        }, "ollama-init");
        ollamaThread.setDaemon(true);
        ollamaThread.start();

        MainLayout mainLayout = new MainLayout();

        Scene scene = new Scene(mainLayout, MIN_WIDTH, MIN_HEIGHT);
        scene.getStylesheets().add(getClass().getResource("/styles/app.css").toExternalForm());

        primaryStage.setTitle(APP_TITLE);
        primaryStage.setScene(scene);
        primaryStage.setMinWidth(MIN_WIDTH);
        primaryStage.setMinHeight(MIN_HEIGHT);
        primaryStage.setOnCloseRequest(e -> {
            System.out.println("[Aegis] Window closing, stopping Ollama...");
            ollamaManager.stop();
        });
        primaryStage.show();

        long uiReady = System.currentTimeMillis() - appStart;
        System.out.println("[Aegis] UI ready in " + uiReady + "ms");
    }

    @Override
    public void stop() {
        System.out.println("[Aegis] JavaFX stop() called, stopping Ollama...");
        if (ollamaManager != null) {
            ollamaManager.stop();
        }
    }

    public OllamaClient getOllamaClient() {
        return ollamaClient;
    }

    public OllamaManager getOllamaManager() {
        return ollamaManager;
    }

    public static void main(String[] args) {
        launch(args);
    }
}
