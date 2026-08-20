package aegis.gui;

import javafx.application.Application;
import javafx.scene.Scene;
import javafx.scene.image.Image;
import javafx.stage.Stage;

import java.util.Objects;

public class AegisApp extends Application {

    private static final String APP_TITLE = "Aegis PreFlight — Security for AI Coding";
    private static final int MIN_WIDTH = 1200;
    private static final int MIN_HEIGHT = 720;

    @Override
    public void start(Stage primaryStage) {
        Image icon = new Image(Objects.requireNonNull(
            getClass().getResourceAsStream("/styles/applogo.png")));
        primaryStage.getIcons().add(icon);

        MainLayout mainLayout = new MainLayout();

        Scene scene = new Scene(mainLayout, MIN_WIDTH, MIN_HEIGHT);
        scene.getStylesheets().add(getClass().getResource("/styles/app.css").toExternalForm());

        primaryStage.setTitle(APP_TITLE);
        primaryStage.setScene(scene);
        primaryStage.setMinWidth(MIN_WIDTH);
        primaryStage.setMinHeight(MIN_HEIGHT);
        primaryStage.show();
    }

    public static void main(String[] args) {
        launch(args);
    }
}
