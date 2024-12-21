package model;

import java.io.FileOutputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.util.*;
/**
 * This class provides functionalities to manage a Java KeyStore (JKS).
 * It allows creating, loading, saving, and manipulating key pairs and certificates within the KeyStore.
 */
public class KeyStoreMenager {
    private KeyStore keyStore;
    private String keyStoreFilePath;
    private char[] mainPassword;

    /**
     * Constructs a KeyStoreMenager instance and initializes the KeyStore.
     *
     * @param filePath The path where the KeyStore will be saved.
     * @param password The password used to secure the KeyStore.
     * @throws Exception If an error occurs during KeyStore initialization.
     */
    public KeyStoreMenager(String filePath, char[] password) throws Exception {
        this.keyStoreFilePath = filePath;
        this.mainPassword = password;
        this.keyStore = KeyStore.getInstance("JKS");
        createEmptyKeyStore();
    }

    /**
     * Creates an empty KeyStore and saves it to the specified file path.
     *
     * @throws Exception If an error occurs during KeyStore creation or saving.
     */
    private void createEmptyKeyStore() throws Exception {
            keyStore.load(null, mainPassword); // Create a new KeyStore
            saveKeyStore();
    }

    /**
     * Saves the KeyStore to the specified file path.
     *
     * @throws Exception If an error occurs during saving.
     */
    private void saveKeyStore() throws Exception {
        try (FileOutputStream fos = new FileOutputStream(keyStoreFilePath)) {
            keyStore.store(fos, mainPassword);
        }
    }

    /**
     * Lists all entries in the KeyStore.
     *
     * @param passwd The password used to access private keys in the KeyStore.
     * @return A map containing aliases as keys and KeyPairs as values.
     * @throws Exception If an error occurs while accessing the KeyStore.
     */
    public Map<String,KeyPair> listEntries(char[] passwd) throws Exception {
        Map<String, KeyPair> record = new HashMap<>();
        Enumeration<String> e = keyStore.aliases();
        PrivateKey kr = null;
        PublicKey ku = null;
        while (e.hasMoreElements()) {
            String alias = e.nextElement();
            if (keyStore.isKeyEntry(alias)) {
                kr = (PrivateKey) keyStore.getKey(alias, passwd);
                java.security.cert.Certificate cert = keyStore.getCertificate(alias);
                ku = cert.getPublicKey();
                record.put(alias,new KeyPair(ku,kr));
            }
        }
        //System.out.println(record);
        return record;
    }

    /**
     * Creates a new RSA key pair and stores it in the KeyStore with a self-signed certificate.
     *
     * @param alias The alias under which the key pair will be stored.
     * @param entryPassword The password for the key pair entry.
     * @throws Exception If an error occurs during key pair generation or storage.
     */
    public void createAndStoreKeyPair(String alias, char[] entryPassword) throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(512);
        KeyPair keyPair = keyPairGen.generateKeyPair();

        // Create a self-signed certificate
        Certificate certificate = SelfSignedCertificateGenerator.generateCertificate(keyPair, "CN=Test", 365);

        keyStore.setKeyEntry(alias, keyPair.getPrivate(), entryPassword, new Certificate[]{certificate});
        saveKeyStore();
        System.out.println("Key pair created and stored with alias: " + alias);
    }

    /**
     * Retrieves a key pair from the KeyStore.
     *
     * @param alias The alias of the key pair to retrieve.
     * @param entryPassword The password for the key pair entry.
     * @return The retrieved KeyPair.
     * @throws Exception If the alias does not exist or an error occurs during retrieval.
     */
    public KeyPair retrieveKeyPair(String alias, char[] entryPassword) throws Exception {
        Key key = keyStore.getKey(alias, entryPassword);
        if (key instanceof PrivateKey) {
            Certificate cert = keyStore.getCertificate(alias);
            PublicKey publicKey = cert.getPublicKey();
            System.out.println("Key pair retrieved with alias: " + alias);
            return new KeyPair(publicKey, (PrivateKey) key);
        }
        throw new KeyStoreException("No key pair found for alias: " + alias);
    }

    /**
     * Deletes an entry from the KeyStore.
     *
     * @param alias The alias of the entry to delete.
     * @throws Exception If the alias does not exist or an error occurs during deletion.
     */
    public void deleteEntry(String alias) throws Exception {
        if (keyStore.containsAlias(alias)) {
            keyStore.deleteEntry(alias);
            saveKeyStore();
            System.out.println("Entry deleted: " + alias);
        } else {
            System.out.println("Alias not found: " + alias);
        }
    }
}

