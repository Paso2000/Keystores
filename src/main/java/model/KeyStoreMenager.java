package model;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.util.*;

public class KeyStoreMenager {
    private KeyStore keyStore;
    private String keyStoreFilePath;
    private char[] mainPassword;

    public KeyStoreMenager(String filePath, char[] password) throws Exception {
        this.keyStoreFilePath = filePath;
        this.mainPassword = password;
        this.keyStore = KeyStore.getInstance("JKS");
        createEmptyKeyStore();
    }

    // Load or create a KeyStore
    private void createEmptyKeyStore() throws Exception {
            keyStore.load(null, mainPassword); // Create a new KeyStore
            saveKeyStore();
    }

    // Save the KeyStore
    private void saveKeyStore() throws Exception {
        try (FileOutputStream fos = new FileOutputStream(keyStoreFilePath)) {
            keyStore.store(fos, mainPassword);
        }
    }

    // List all entries in the KeyStore
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
        return record;
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
}

