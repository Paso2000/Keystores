package model;

import org.apache.commons.io.output.CountingOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import utils.Header;
import utils.Options;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Objects;

/**
 * This class provides cryptographic functions to protect and verify file and message integrity.
 * It uses various hash algorithms (MD5, SHA1, SHA256, etc.) and supports HMAC with a shared secret.
 * Headers are added to the output to store metadata about the digest process, ensuring secure verification.
 */
public class HashAlgorithm {

    private int iterationCount = 100; // Number of iterations for PBKDF2
    private byte[] salt = Hex.decode("0102030405060708"); // Salt used in key derivation
    private long bytetoDelete; // Tracks header size in bytes
    private int macLength = 64; // Length of the generated MAC

    SecretKey macKey = new SecretKeySpec(
            Hex.decode(
                    "2ccd85dfc8d18cb5d84fef4b19855469" +
                            "9fece6e8692c9147b0da983f5b7bd413"), "HmacSHA256");

    /**
     * Protects a message by calculating a secure hash or MAC and embedding metadata in the output.
     *
     * @param input     The message to hash.
     * @param algorithm The hash or MAC algorithm to use (e.g., SHA256, HmacSHA256).
     * @param password  The secret key or password for HMAC-based algorithms.
     * @return A Base64-encoded string containing the protected message and header metadata.
     * @throws Exception If any cryptographic operation fails.
     */
    public String protectMessageHash(String input, String algorithm, String password) throws Exception {
        //hash or Mac calculation
        byte[] macResult = this.hashBytes(input.getBytes(), algorithm, password);
        //create header with the hash/Mac in data section
        Header header = new Header(Options.OP_SIGNED, Options.OP_NONE_ALGORITHM, algorithm, macResult);
        ByteArrayOutputStream arrayOut = new ByteArrayOutputStream();
        CountingOutputStream outputStream = new CountingOutputStream(arrayOut);
        //write the header
        header.save(outputStream);
        //calculate how long is the heder
        bytetoDelete = outputStream.getByteCount();
        //write the input in the clear
        outputStream.write(input.getBytes());
        outputStream.close();

        return Base64.getEncoder().encodeToString(arrayOut.toByteArray());
    }

    /**
     * Verifies a previously protected message by comparing the stored hash or MAC with a recalculated one.
     *
     * @param datas       The Base64-encoded protected message containing the header and original message.
     * @param hashFunction The hash or MAC algorithm to use (e.g., SHA256, HmacSHA256).
     * @param password     The secret key or password for HMAC-based algorithms.
     * @return The original message if verification succeeds, or null otherwise.
     * @throws Exception If any cryptographic operation fails.
     */
    public String verifyHashMessage(String datas, String hashFunction, String password) throws Exception {
        try {
            byte[] data = Base64.getDecoder().decode(datas);
            ByteArrayInputStream IStream = new ByteArrayInputStream(data);
            Header header = new Header();
            //read the header
            header.load(IStream);
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            //write the data without the header
            outputStream.write(data, (int) bytetoDelete, (int) (data.length - bytetoDelete));
            outputStream.close();
            return outputStream.toString();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Computes a hash or MAC for the provided byte array using the specified algorithm and password.
     *
     * @param fileBytes  The data to hash.
     * @param algorithm  The hash or MAC algorithm to use (e.g., SHA256, HmacSHA256).
     * @param password   The secret key or password for HMAC-based algorithms.
     * @return The calculated hash or MAC as a byte array.
     * @throws NoSuchAlgorithmException If the specified algorithm is not available.
     * @throws IOException              If an I/O error occurs during processing.
     * @throws NoSuchProviderException  If the cryptographic provider is unavailable.
     * @throws InvalidKeySpecException  If the password cannot be converted into a secret key.
     * @throws InvalidKeyException      If the secret key is invalid for the specified algorithm.
     */
    public byte[] hashBytes(byte[] fileBytes, String algorithm, String password)
            throws NoSuchAlgorithmException, IOException, NoSuchProviderException, InvalidKeySpecException, InvalidKeyException {
        // control if the algorithm is MAC or no
        if (Objects.equals(algorithm, "HmacMD5") || Objects.equals(algorithm, "HmacSHA1") ||
                Objects.equals(algorithm, "HmacSHA256") || Objects.equals(algorithm, "HmacSHA384") ||
                Objects.equals(algorithm, "HmacSHA512")) {

            Security.addProvider(new BouncyCastleProvider());
            //insert the algorithm
            Mac mac = Mac.getInstance(algorithm, "BC");
            //create the secret key
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterationCount, macLength);
            SecretKey secretKey = skf.generateSecret(spec);
            mac.init(secretKey);
            mac.init(macKey);

            //calculate the MAC
            try (ByteArrayInputStream inputStream = new ByteArrayInputStream(fileBytes)) {
                byte[] buffer = new byte[1024];
                int bytesRead;
                while ((bytesRead = inputStream.read(buffer)) != -1) {
                    mac.update(buffer, 0, bytesRead);
                }
            }
            return mac.doFinal();
        } else {
            //else calculate the hash
            InputStream inputStream = new ByteArrayInputStream(fileBytes);
            MessageDigest digest = MessageDigest.getInstance(algorithm);
            digest.update(password.getBytes());

            try (DigestInputStream digestInputStream = new DigestInputStream(inputStream, digest)) {
                byte[] buffer = new byte[4096];
                while (digestInputStream.read(buffer) != -1) {}
                return digest.digest();
            }
        }
    }
}