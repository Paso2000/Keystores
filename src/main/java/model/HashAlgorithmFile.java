package model;

import org.apache.commons.io.output.CountingOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import utils.Header;
import utils.Options;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;
import java.util.Arrays;

/**
 * This class handles file hashing and integrity protection using hash or MAC algorithms.
 * It allows encrypting a file by adding a digest and header information, as well as verifying
 * the integrity of previously hashed files.
 */
public class HashAlgorithmFile {
    private long bytetoDelete; // Tracks header size in bytes
    private final HashAlgorithm hashAlgorithm = new HashAlgorithm();

    /**
     * Hashes the content of a file and saves it in an encrypted format with header metadata.
     *
     * @param input     The file to be hashed and saved.
     * @param algorithm The hash or MAC algorithm to use (e.g., SHA256, HmacSHA256).
     * @param password  The secret key or password for HMAC-based algorithms.
     * @return An array containing:
     *         - The computed hash as a hexadecimal string.
     *         - The name of the hash algorithm used.
     * @throws Exception If any cryptographic or I/O operation fails.
     */
    public String[] hashFileEncrypt(File input, String algorithm, String password) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        //Get all the bytes from the file
        Path inputPath = input.toPath();
        byte[] fileBytes = Files.readAllBytes(inputPath);


        // Creating the output file path with ".hsh" extension
        String encryptedFilePath = input.getParent() + File.separator +
                input.getName().replaceFirst("[.][^.]+$", "") + ".hsh";
        File encryptedFile = new File(encryptedFilePath);

        // Compute the hash of the file
        byte[] hash = hashAlgorithm.hashBytes(fileBytes, algorithm, password);

        // Create and save the header
        Header header = new Header(Options.OP_SIGNED, Options.OP_NONE_ALGORITHM, algorithm, hash);

        try (FileOutputStream fileOut = new FileOutputStream(encryptedFile);
             CountingOutputStream outputStream = new CountingOutputStream(fileOut)) {
            header.save(outputStream);
            bytetoDelete = outputStream.getByteCount(); // Store header size

            // Write the file data after the header
            outputStream.write(fileBytes);
        }
        return new String[]{Hex.toHexString(hash), algorithm};
    }

    /**
     * Verifies the hash of an encrypted file, compares it with the stored hash,
     * and reconstructs the original file content if verification succeeds.
     *
     * @param encryptedInput The file containing the hashed and encrypted data.
     * @param algorithm      The hash or MAC algorithm to use (e.g., SHA256, HmacSHA256).
     * @param password       The secret key or password for HMAC-based algorithms.
     * @return An array containing:
     *         - The stored hash from the file header.
     *         - The recalculated hash of the file content.
     * @throws Exception If any cryptographic or I/O operation fails.
     */
    public String[] hashVerifyFile(File encryptedInput, String algorithm, String password) throws Exception {
        String storedHash;
        //Get the bytes of the file
        Path encryptedPath = encryptedInput.toPath();
        byte[] bytes = Files.readAllBytes(encryptedPath);

        // Extract the file bytes after the header
        byte[] fileBytes = Arrays.copyOfRange(bytes, (int) bytetoDelete, bytes.length);

        // Recalculate the hash of the file content
        String recalculatedHash = Hex.toHexString(hashAlgorithm.hashBytes(fileBytes, algorithm, password));

        // Load the header from the file
        Header header = new Header();
        String verifiedFilePath = encryptedInput.getParent() + File.separator +
                encryptedInput.getName().replaceFirst("[.][^.]+$", "") + "_decrypted.cla";
        File verifiedFile = new File(verifiedFilePath);
            try (FileOutputStream fileOut = new FileOutputStream(verifiedFile);
                 ByteArrayInputStream cIn = new ByteArrayInputStream(bytes)) {
                //take the header
                header.load(cIn);
                //Get the hash previously calculated
                storedHash = Hex.toHexString(header.getData());
                if (storedHash.equals(recalculatedHash)) {
                    byte[] buffer = new byte[4096];
                    int bytesRead;
                    while ((bytesRead = cIn.read(buffer)) != -1) {
                        fileOut.write(buffer, 0, bytesRead);
                    }

                    return new String[]{storedHash, recalculatedHash};
                }
            }
        return new String[]{storedHash, recalculatedHash};
    }
}