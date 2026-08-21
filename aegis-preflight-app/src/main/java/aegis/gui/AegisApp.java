package aegis.gui;

import aegis.ai.EmbeddedLLM;
import javafx.application.Application;
import javafx.scene.Scene;
import javafx.scene.image.Image;
import javafx.stage.Stage;

import java.util.Objects;

public class AegisApp extends Application {

    private static final String APP_TITLE = "Aegis PreFlight \u2014 Security for AI Coding";
    private static final int MIN_WIDTH = 1200;
    private static final int MIN_HEIGHT = 720;

    @Override
    public void start(Stage primaryStage) {
        long appStart = System.currentTimeMillis();

        Image icon = new Image(Objects.requireNonNull(
            getClass().getResourceAsStream("/styles/app-logo.png")));
        primaryStage.getIcons().add(icon);

        Runtime.getRuntime().addShutdownHook(new Thread(EmbeddedLLM.get()::stop));

        // Auto-start the PACKED LLM engine (llama-server + bundled GGUF) in the
        // background so the first Security Report is ready as early as possible.
        // The UI never waits for it — the deterministic report shows instantly.
        Thread llmThread = new Thread(() -> {
            long start = System.currentTimeMillis();
            boolean ok = EmbeddedLLM.get().ensureStarted();
            if (ok) {
                aegis.ai.LocalSecurityLLM.warmup();
                System.out.println("[Aegis] embedded LLM ready in "
                    + (System.currentTimeMillis() - start) + "ms (model: "
                    + aegis.ai.LocalSecurityLLM.MODEL + ")");
            } else {
                System.err.println("[Aegis] embedded LLM unavailable (non-fatal): "
                    + EmbeddedLLM.get().getLastError()
                    + " — reports will use the deterministic structured fallback.");
            }
        }, "embedded-llm-init");
        llmThread.setDaemon(true);
        llmThread.start();

        MainLayout mainLayout = new MainLayout();

        Scene scene = new Scene(mainLayout, MIN_WIDTH, MIN_HEIGHT);
        scene.getStylesheets().add(getClass().getResource("/styles/app.css").toExternalForm());

        primaryStage.setTitle(APP_TITLE);
        primaryStage.setScene(scene);
        primaryStage.setMinWidth(MIN_WIDTH);
        primaryStage.setMinHeight(MIN_HEIGHT);
        primaryStage.setOnCloseRequest(e -> {
            System.out.println("[Aegis] Window closing, stopping embedded LLM...");
            EmbeddedLLM.get().stop();
        });
        primaryStage.show();

        long uiReady = System.currentTimeMillis() - appStart;
        System.out.println("[Aegis] UI ready in " + uiReady + "ms");
    }

    @Override
    public void stop() {
        System.out.println("[Aegis] JavaFX stop() called, stopping embedded LLM...");
        EmbeddedLLM.get().stop();
    }

    public static void main(String[] args) {
        launch(args);
    }
}
