package model;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.util.Enumeration;

public class KeyStoreMenager {
    private KeyStore keyStore;
    private String keyStoreFilePath;
    private char[] mainPassword;

    public KeyStoreMenager(String filePath, char[] password) throws Exception {
        this.keyStoreFilePath = filePath;
        this.mainPassword = password;
        this.keyStore = KeyStore.getInstance("JKS");
        loadKeyStore();
    }

    // Load or create a KeyStore
    private void loadKeyStore() throws Exception {
        try (FileInputStream fis = new FileInputStream(keyStoreFilePath)) {
            keyStore.load(fis, mainPassword);
        } catch (Exception e) {
            System.out.println("KeyStore not found, creating a new one...");
            keyStore.load(null, mainPassword); // Create a new KeyStore
            saveKeyStore();
        }
    }

    // Save the KeyStore
    private void saveKeyStore() throws Exception {
        try (FileOutputStream fos = new FileOutputStream(keyStoreFilePath)) {
            keyStore.store(fos, mainPassword);
        }
    }

    // List all entries in the KeyStore
    public void listEntries() throws Exception {
        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            System.out.println("Alias: " + alias);
            System.out.println("Entry Type: " + (keyStore.isKeyEntry(alias) ? "Key" : "Trusted Certificate"));
        }
    }

    // Create a new key pair and store it in the KeyStore
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

    // Retrieve and use a key pair from the KeyStore
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

    // Delete an entry from the KeyStore
    public void deleteEntry(String alias) throws Exception {
        if (keyStore.containsAlias(alias)) {
            keyStore.deleteEntry(alias);
            saveKeyStore();
            System.out.println("Entry deleted: " + alias);
        } else {
            System.out.println("Alias not found: " + alias);
        }
    }

    public static void main(String[] args) {
        try {
            String keyStoreFile = "keystore.jks";
            char[] mainPassword = "password".toCharArray();

            KeyStoreMenager manager = new KeyStoreMenager(keyStoreFile, mainPassword);

            System.out.println("1. List entries:");
            manager.listEntries();

            System.out.println("\n2. Create and store a key pair:");
            char[] entryPassword = "keypass".toCharArray();
            manager.createAndStoreKeyPair("testAlias", entryPassword);

            System.out.println("\n3. List entries again:");
            manager.listEntries();

            System.out.println("\n4. Retrieve and use a key pair:");
            KeyPair keyPair = manager.retrieveKeyPair("testAlias", entryPassword);

            System.out.println("\n5. Delete an entry:");
            manager.deleteEntry("testAlias");

            System.out.println("\n6. List entries again:");
            manager.listEntries();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

