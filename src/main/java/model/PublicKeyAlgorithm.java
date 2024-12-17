package model;

import utils.Header;
import utils.Options;

import javax.crypto.Cipher;
import java.io.*;
import java.nio.file.Files;
import java.security.Key;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Objects;

public class PublicKeyAlgorithm {
    private static final int ENCRYPT_BLOCK_SIZE = 53; // Blocchi da 53 byte per criptare
    private static final int DECRYPT_BLOCK_SIZE = 64; // Blocchi da 64 byte per decriptare


    /**
     * Encrypts a file using the provided public key.
     *
     * @param inputFilePath  Path to the input file to encrypt.
     * @param outputFilePath Path to save the encrypted output file.
     * @param publicKey      Public key used for encryption.
     * @param algorithmName  Name of the cryptographic algorithm (e.g., "RSA").
     * @throws Exception If an error occurs during encryption.
     */
    public String encryptFile(String inputFilePath, String outputFilePath, Key publicKey, String algorithmName) throws Exception {
        Cipher cipher = Cipher.getInstance(algorithmName);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        try (FileInputStream inputStream = new FileInputStream(inputFilePath);
             FileOutputStream outputStream = new FileOutputStream(outputFilePath)) {
            Header header = new Header(Options.OP_PUBLIC_CIPHER, algorithmName , Options.OP_NONE_ALGORITHM,publicKey.getEncoded());
            header.save(outputStream);
            byte[] buffer = new byte[ENCRYPT_BLOCK_SIZE];
            int bytesRead;

            while ((bytesRead = inputStream.read(buffer)) != -1) {
                byte[] blockToEncrypt = (bytesRead < ENCRYPT_BLOCK_SIZE)
                        ? trimBytes(buffer, bytesRead)
                        : buffer;

                byte[] encryptedBlock = cipher.doFinal(blockToEncrypt);
                outputStream.write(encryptedBlock);
            }
            return outputFilePath;
        }
    }

    /**
     * Trims a byte array to the specified length.
     * Useful when a block is smaller than the expected size.
     *
     * @param buffer The original buffer to trim.
     * @param length The desired length of the trimmed array.
     * @return A trimmed byte array.
     */
    private static byte[] trimBytes(byte[] buffer, int length) {
        byte[] trimmed = new byte[length];
        System.arraycopy(buffer, 0, trimmed, 0, length);
        return trimmed;
    }

    /**
     * Decrypts a file using the provided private key.
     *
     * @param inputFilePath  Path to the input file to decrypt.
     * @param outputFilePath Path to save the decrypted output file.
     * @param privateKey     Private key used for decryption.
     * @param algorithmName  Name of the cryptographic algorithm (e.g., "RSA").
     * @throws Exception If an error occurs during decryption.
     */
    public boolean decryptFile(String inputFilePath, String outputFilePath, Key privateKey, String algorithmName) throws Exception {
        boolean canBeDeciper = true;
        Cipher cipher = Cipher.getInstance(algorithmName);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        try (FileInputStream inputStream = new FileInputStream(inputFilePath);
             FileOutputStream outputStream = new FileOutputStream(outputFilePath)) {
            Header header = new Header();
            header.load(inputStream);
            if (header.getOperation() == Options.OP_PUBLIC_CIPHER && Objects.equals(header.getAlgorithm1(), algorithmName)) {
                byte[] buffer = new byte[DECRYPT_BLOCK_SIZE];
                int bytesRead;

                while ((bytesRead = inputStream.read(buffer)) != -1) {
                    byte[] blockToDecrypt = (bytesRead < DECRYPT_BLOCK_SIZE)
                            ? trimBytes(buffer, bytesRead)
                            : buffer;

                    byte[] decryptedBlock = cipher.doFinal(blockToDecrypt);
                    outputStream.write(decryptedBlock);
                }
            }else canBeDeciper = false;
            return canBeDeciper;
        }
    }

}
