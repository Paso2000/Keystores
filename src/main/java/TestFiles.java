
import model.PBEAlgorithmFile;
import java.io.File;

public class TestFiles {
    public static void main(String[] args) {
        try {
            PBEAlgorithmFile pbeFile = new PBEAlgorithmFile();

            File pdfFile = new File("C:/Users/giamm/Desktop/Tema 1.pdf");
            String password = "yourpassword";
            String algorithm = "PBEWithMD5AndDES";

            System.out.println("Inizio crittografia del file...");
            pbeFile.Encrypt(pdfFile, password, algorithm);
            System.out.println("File crittografato con successo!");

            File encryptedFile = new File(pdfFile.getParent() + File.separator + pdfFile.getName().replaceFirst("[.][^.]+$", "") + ".CIF");

            System.out.println("Inizio decifratura del file...");
            pbeFile.Decrypt(encryptedFile, password, algorithm);
            System.out.println("File decifrato con successo!");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
