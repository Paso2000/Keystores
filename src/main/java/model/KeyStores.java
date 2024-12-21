package model;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Enumeration;

/**
 * This class provides methods for interacting with a Java KeyStore (JKS).
 * It supports loading an existing KeyStore and retrieving keys from it.
 */
public class KeyStores {
    KeyStore keyStore;

    /**
     * Loads an existing KeyStore from a specified file.
     *
     * @param fileName The file name of the KeyStore.
     * @param passwd The password to access the KeyStore.
     * @throws KeyStoreException If the KeyStore instance cannot be created.
     * @throws IOException If there is an error reading the KeyStore file.
     * @throws CertificateException If any of the certificates in the KeyStore cannot be loaded.
     * @throws NoSuchAlgorithmException If the algorithm for recovering the KeyStore's integrity cannot be found.
     */
    public void KeyStoring(String fileName, char[] passwd) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        keyStore = KeyStore.getInstance("JKS");
        keyStore.load(new FileInputStream(fileName),passwd);
    }

    /**
     * Retrieves a key pair (public and private key) from the KeyStore.
     *
     * @param passwd The password to access private keys in the KeyStore.
     * @return A KeyPair containing the public and private keys from the KeyStore.
     * @throws KeyStoreException If the KeyStore is not initialized or another error occurs.
     * @throws UnrecoverableKeyException If the key cannot be recovered (e.g., wrong password).
     * @throws NoSuchAlgorithmException If the algorithm for recovering the key cannot be found.
     */
    public KeyPair getKeyFromStorage(char[] passwd) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
        Enumeration<String> e = keyStore.aliases();
        PrivateKey kr= null;
        PublicKey ku = null;
        while (e.hasMoreElements()) {
            String alias = e.nextElement();
            if (keyStore.isKeyEntry(alias)) {
                 kr = (PrivateKey) keyStore.getKey(alias, passwd);
                java.security.cert.Certificate cert = keyStore.getCertificate(alias);
                ku = cert.getPublicKey();
            }
        }
    return new KeyPair(ku, kr);
    }
}
