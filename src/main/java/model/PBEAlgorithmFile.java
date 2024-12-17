package model;

import org.bouncycastle.jcajce.io.CipherOutputStream;
import org.bouncycastle.util.encoders.Hex;
import utils.Header;
import utils.Options;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Used MVC pattern to manage GUI
 * this class is the pattern model, is used by controller.
 * PBEAlgorithm is logic class to handle encryption/decryption of files.
 */
public class PBEAlgorithmFile {
    private int iterationCount = 100;
    private byte[] salt = Hex.decode("0102030405060708");

    /**
     * Methods to encrypt a File.
     *
     * @param input     String
     * @param passwd    String
     * @param algorithm String
     * @return a ciphertext File.CIF
     */
    public void Encrypt(File input, String passwd, String algorithm) throws Exception {

        Path inputPath = input.toPath();
        byte[] fileBytes = Files.readAllBytes(inputPath);

        // Generating symmetric key for the chosen algorithm
        PBEKeySpec pbeKeySpec = new PBEKeySpec(passwd.toCharArray());
        SecretKeyFactory keyFact = SecretKeyFactory.getInstance(algorithm);
        SecretKey pbeKey = keyFact.generateSecret(pbeKeySpec);

        // Creating the encryption cipher using salt, IC and the key
        PBEParameterSpec pbeParamSpec = new PBEParameterSpec(salt, iterationCount);
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, pbeKey, pbeParamSpec);

        // creating the path for the file .CIF
        String encryptedFilePath = input.getParent() + File.separator + input.getName().replaceFirst("[.][^.]+$", "") + ".CIF";
        File encryptedFile = new File(encryptedFilePath);
        //creating the header with the correspondents data
        Header header = new Header(Options.OP_SYMMETRIC_CIPHER, algorithm, Options.OP_NONE_ALGORITHM, salt);

        //create the output stram
        try (FileOutputStream fileOut = new FileOutputStream(encryptedFile);
             CipherOutputStream cOut = new CipherOutputStream(fileOut, cipher)) {
            //save the header on the output stream
            if (header.save(cOut)) {
                System.out.println("Symmetric encryption: " + Options.OP_SYMMETRIC_CIPHER);
                System.out.println("Algorithm: " + algorithm);
                System.out.println("With salt:" + salt);
                System.out.println("Iteretion count:" + iterationCount);

            } else {
                System.out.println("load non andato a buon fine");
            }
            //write and encrypt the file bytes on the output stream
            cOut.write(fileBytes);

        }

        System.out.println("File cifrato salvato come: " + encryptedFile.getAbsolutePath());
    }

    /**
     * Methods to decrypt a File.CIF
     *
     * @param encryptedInput String
     * @param passwd         String
     * @param algorithm      String
     * @return a File_decrypted.cla
     */
    public void Decrypt(File encryptedInput, String passwd, String algorithm) throws Exception {
        Path encryptedPath = encryptedInput.toPath();
        byte[] encryptedBytes = Files.readAllBytes(encryptedPath);

        // Generating symmetric key for the chosen algorithm
        PBEKeySpec pbeKeySpec = new PBEKeySpec(passwd.toCharArray());
        SecretKeyFactory keyFact = SecretKeyFactory.getInstance(algorithm);
        SecretKey pbeKey = keyFact.generateSecret(pbeKeySpec);

        // Creating the encryption cipher using salt, IC and the key
        PBEParameterSpec pbeParamSpec = new PBEParameterSpec(salt, iterationCount);
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, pbeKey, pbeParamSpec);

        // Creating the path for the decrypted file
        String decryptedFilePath = encryptedInput.getParent() + File.separator + encryptedInput.getName().replaceFirst("[.][^.]+$", "") + "_decrypted.cla";
        File decryptedFile = new File(decryptedFilePath);

        //create the file outputStream
        try (FileOutputStream fileOut = new FileOutputStream(decryptedFile);
             //create the CipherInputStream using the cipher and an ByteArrayInputStream that contains encryptedBytes
             CipherInputStream cIn = new CipherInputStream(new ByteArrayInputStream(encryptedBytes), cipher)) {
            byte[] buffer = new byte[4096];
            int bytesRead;
            //writes every byte on the buffer decrypting it
            while ((bytesRead = cIn.read(buffer)) != -1) {
                fileOut.write(buffer, 0, bytesRead);
            }
            //for debugging
            //System.out.println("Decrypted file path: " + decryptedFile.getAbsolutePath());
        }
    }
}
