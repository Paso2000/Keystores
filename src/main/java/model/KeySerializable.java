package model;

import java.io.*;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

/**
 * This class provides serialization and deserialization functionality for public and private keys.
 * It allows keys to be serialized into a stream and reconstructed from it.
 */
public class KeySerializable implements Serializable {

    /**
     * The public key associated with this object.
     */
    public PublicKey pku;

    /**
     * The private key associated with this object.
     */
    public PrivateKey pkr;

    /**
     * Reads and reconstructs a {@link KeyPair} object from the provided input stream.
     *
     * @param stream The input stream containing the serialized public and private keys.
     * @return A {@link KeyPair} object containing the reconstructed public and private keys.
     * @throws IOException              If an I/O error occurs during reading.
     * @throws ClassNotFoundException   If the serialized objects cannot be found.
     * @throws InvalidKeySpecException  If the key specifications are invalid.
     * @throws NoSuchAlgorithmException If the specified algorithm (e.g., "RSA") is not available.
     */
    @Serial
    public KeyPair readObject(ObjectInputStream stream)
            throws IOException, ClassNotFoundException, InvalidKeySpecException, NoSuchAlgorithmException {

        // Read the byte arrays for the keys from the stream
        byte[] publicKeyBytes = (byte[]) stream.readObject();
        byte[] privateKeyBytes = (byte[]) stream.readObject();

        // Use KeyFactory to reconstruct the keys (example with RSA)
        java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance("RSA");

        // Reconstruct the PublicKey
        java.security.spec.X509EncodedKeySpec pubKeySpec = new java.security.spec.X509EncodedKeySpec(publicKeyBytes);
        pku = keyFactory.generatePublic(pubKeySpec);

        // Reconstruct the PrivateKey
        java.security.spec.PKCS8EncodedKeySpec privKeySpec = new java.security.spec.PKCS8EncodedKeySpec(privateKeyBytes);
        pkr = keyFactory.generatePrivate(privKeySpec);

        return new KeyPair(pku, pkr);
    }

    /**
     * Serializes the provided public and private keys into the given output stream.
     *
     * @param stream The output stream to write the keys to.
     * @param pku    The public key to be serialized.
     * @param pkr    The private key to be serialized.
     * @throws IOException If an I/O error occurs during writing.
     */
    @Serial
    public void writeObject(ObjectOutputStream stream, PublicKey pku, PrivateKey pkr) throws IOException {
        // Serialize the encoded form of the public key
        stream.writeObject(pku.getEncoded());
        // Serialize the encoded form of the private key
        stream.writeObject(pkr.getEncoded());
    }
}
