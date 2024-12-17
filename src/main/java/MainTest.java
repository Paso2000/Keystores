import controller.PBEController;
import model.*;
import view.View;

public class MainTest {
    public static void main(String[] args) {
        View view = new View();
        PBEController controller = new PBEController(view);
    }
}