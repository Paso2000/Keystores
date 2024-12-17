package model;

import org.apache.commons.io.output.CountingOutputStream;
import org.bouncycastle.util.encoders.Hex;
import utils.Header;
import utils.Options;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.util.Arrays;

/**
 * This class provides methods for signing and verifying files using digital signatures.
 * It supports generating and verifying signatures based on provided cryptographic algorithms.
 */
public class DigitalSignAlgorithm {

    /**
     * Stores the number of bytes to delete (size of the header) during the verification process.
     */
    public long bytetoDelete = 82;

    /**
     * Signs the given file with the provided private key and algorithm.
     *
     * @param file      The file to be signed.
     * @param algorithm The cryptographic algorithm to use (e.g., "SHA256withDSA").
     * @param pkr       The private key for signing the file.
     * @return A String array containing:
     *         - The hexadecimal representation of the generated signature.
     *         - The path to the signed file (.SIG extension).
     * @throws Exception If an error occurs during file reading, signing, or saving.
     */
    public String[] Sign(File file, String algorithm, PrivateKey pkr) throws Exception {
        byte[] fileBytes = Files.readAllBytes(Path.of(file.getPath()));
        String encryptedFilePath = file.getParent() + File.separator +
                file.getName().replaceFirst("[.][^.]+$", "") + ".SIG";
        File encryptedFile = new File(encryptedFilePath);
        Signature dsa = Signature.getInstance(algorithm);
        dsa.initSign(pkr);
        dsa.update(fileBytes);

        byte[] signature = dsa.sign();
        System.out.println(Hex.toHexString(signature));
        Header header = new Header(Options.OP_SIGNED, Options.OP_NONE_ALGORITHM, algorithm, signature);
        FileOutputStream fOut = new FileOutputStream(encryptedFile);
        CountingOutputStream outputStream = new CountingOutputStream(fOut);
        header.save(outputStream);
        bytetoDelete = outputStream.getByteCount(); // Store header size
        fOut.write(fileBytes);
        fOut.close();
        return new String[]{Hex.toHexString(signature), encryptedFilePath};
    }

    /**
     * Verifies the signature of the given file using the provided public key and algorithm.
     *
     * @param file      The file whose signature is to be verified.
     * @param algorithm The cryptographic algorithm used for verification.
     * @param pku       The public key to verify the file's signature.
     * @return A String array containing:
     *         - The hexadecimal representation of the verified signature.
     *         - The path to the verified file (_verified.VER extension).
     *         Or null if the verification fails.
     * @throws Exception If an error occurs during file reading, signature verification, or saving.
     */
    public String[] Verify(File file, String algorithm, PublicKey pku) throws Exception {
        byte[] bytes = Files.readAllBytes(Path.of(file.getPath()));
        String decryptedFilePath = file.getParent() + File.separator +
                file.getName().replaceFirst("[.][^.]+$", "") + "_verified.VER";
        File decryptdFile = new File(decryptedFilePath);

        try (FileOutputStream fileOut = new FileOutputStream(decryptdFile);
             ByteArrayInputStream cIn = new ByteArrayInputStream(bytes)) {
            Header header = new Header();
            header.load(cIn);
            byte[] fileBytes = Arrays.copyOfRange(bytes, (int) bytetoDelete, bytes.length);
            byte[] calculatedHash = header.getData();
            Signature dsa = Signature.getInstance(algorithm);
            dsa.initVerify(pku);
            dsa.update(fileBytes);
            boolean verify = dsa.verify(calculatedHash);
            if (verify) {
                fileOut.write(fileBytes);
                return new String[]{Hex.toHexString(calculatedHash), decryptedFilePath};
            } else {
                return null;
            }
        }
    }
}