package model;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import org.bouncycastle.crypto.io.InvalidCipherTextIOException;
import org.bouncycastle.jcajce.io.CipherInputStream;
import org.bouncycastle.jcajce.io.CipherOutputStream;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.Streams;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Used MVC pattern to manage GUI
 * this class is the pattern model, is used by controller.
 * PBEAlgorithm is logic class to handle encryption/decryption of strings.
 */
public class PBEAlgorithm {
    private int iterationCount = 100;
    private byte[] salt = Hex.decode("0102030405060708");

    /**
     * Methods to encrypt a string.
     *
     * @param input     String
     * @param passwd    String
     * @param algorithm String
     * @return a ciphertext string
     */
    public String Encrypt(String input, String passwd, String algorithm) throws Exception {
        PBEKeySpec pbeKeySpec = new PBEKeySpec(passwd.toCharArray());
        SecretKeyFactory keyFact = SecretKeyFactory.getInstance(algorithm);
        SecretKey pbeKey = keyFact.generateSecret(pbeKeySpec);

        // Uses PBEParameterSpec (with salt and iteration count)
        PBEParameterSpec pbeParamSpec = new PBEParameterSpec(salt, iterationCount);

        // Initialize cipher with PKCS5Padding padding
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, pbeKey, pbeParamSpec);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        //create the CipherOutputStream using the cipher and a ByteArrayOutputStream
        CipherOutputStream cOut = new CipherOutputStream(bOut, cipher);
        //writes and encrypt the byte
        cOut.write(input.getBytes(StandardCharsets.UTF_8));
        cOut.close();

        return Base64.getEncoder().encodeToString(bOut.toByteArray());
    }

    /**
     * Methods to decrypt a string.
     *
     * @param encryptedInput String
     * @param passwd         String
     * @param algorithm      String
     * @return a plaintext string
     */
    public String Decrypt(String encryptedInput, String passwd, String algorithm) throws Exception {
        try {
            // Decode encrypted input from base64
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedInput);

            PBEKeySpec pbeKeySpec = new PBEKeySpec(passwd.toCharArray());
            SecretKeyFactory keyFact = SecretKeyFactory.getInstance(algorithm);
            SecretKey pbeKey = keyFact.generateSecret(pbeKeySpec);

            // Use the same PBEParameterSpec (with salt and iteration count)
            PBEParameterSpec pbeParamSpec = new PBEParameterSpec(salt, iterationCount);

            // Initialize cipher for decryption with PKCS5Padding padding
            Cipher cipher = Cipher.getInstance(algorithm);

            //Set the cipher for decrypting
            cipher.init(Cipher.DECRYPT_MODE, pbeKey, pbeParamSpec);

            ByteArrayInputStream bIn = new ByteArrayInputStream(encryptedBytes);
            //create the CipherInputStream using the cipher and a ByteArrayInputStream that contains the encryptedBytes
            CipherInputStream cIn = new CipherInputStream(bIn, cipher);
            ByteArrayOutputStream bOut = new ByteArrayOutputStream();
            //Write the full contents of inputStr to the destination stream outputStream decrypting it
            Streams.pipeAll(cIn, bOut);
            cIn.close();

            return new String(bOut.toByteArray(), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            throw new Exception("Error in Base64 decoding or decryption parameters.", e);
        } catch (InvalidCipherTextIOException e) {
            throw new Exception("Error in decryption: changed cipher text or wrong parameters.", e);
        }
    }

}




