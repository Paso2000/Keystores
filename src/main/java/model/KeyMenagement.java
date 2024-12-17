package model;

import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;

/**
 * This class provides functionality for key management operations, including generation,
 * storage, and retrieval of public and private keys.
 */
public class KeyMenagement {

    /**
     * Path to the storage location for the key files.
     */
    private String keyStoragePath;

    /**
     * The length (in bits) of the RSA keys to be generated. Default is 512.
     */
    private int length = 512;

    /**
     * The key pair containing both public and private keys.
     */
    private KeyPair keyPair;

    /**
     * An instance of {@link KeySerializable} for serializing and deserializing keys.
     */
    private KeySerializable keySerializable = new KeySerializable();

    /**
     * Generates a new RSA key pair with the specified length.
     *
     * @return A {@link KeyPair} object containing the generated public and private keys.
     * @throws NoSuchAlgorithmException If the RSA algorithm is not available in the environment.
     */
    public KeyPair keyGeneration() throws NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(length);
        keyPair = kpg.generateKeyPair();
        return keyPair;
    }

    /**
     * Stores the provided public and private keys to the specified file path.
     *
     * @param keyStoragePath The file path where the keys should be stored.
     * @param publicKey      The public key to store.
     * @param privateKey     The private key to store.
     * @throws RuntimeException If an I/O error occurs during the key storage process.
     */
    public void keyStorage(String keyStoragePath, PublicKey publicKey, PrivateKey privateKey) {
        try {
            this.keyStoragePath = keyStoragePath;
            File encryptedFile = new File(this.keyStoragePath);
            FileOutputStream fileOut = new FileOutputStream(encryptedFile);
            ObjectOutputStream os = new ObjectOutputStream(fileOut);
            keySerializable.writeObject(os, publicKey, privateKey);
            os.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Loads a previously stored key pair from the specified file path.
     *
     * @param keyStoragePath The file path where the keys are stored.
     * @param password       The password for key loading (not currently used in this implementation).
     * @return A {@link KeyPair} object containing the loaded public and private keys.
     * @throws IOException              If an I/O error occurs during the key loading process.
     * @throws InvalidKeySpecException  If the key specifications are invalid.
     * @throws NoSuchAlgorithmException If the RSA algorithm is not available in the environment.
     * @throws ClassNotFoundException   If the key class cannot be found during deserialization.
     */
    public KeyPair keyLoad(String keyStoragePath, String password)
            throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, ClassNotFoundException {
        File file = new File(keyStoragePath);
        FileInputStream fIn = new FileInputStream(file);
        ObjectInputStream is = new ObjectInputStream(fIn);
        KeyPair keys = keySerializable.readObject(is);
        is.close();
        return keys;
    }
}
