package model;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Enumeration;

public class KeyStores {
    KeyStore keyStore;


    public void KeyStoring(String fileName, char[] passwd) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        keyStore = KeyStore.getInstance("JKS");
        keyStore.load(new FileInputStream(fileName),passwd);
    }

    public KeyPair getKeyFromStorage(char[] passwd) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
        Enumeration<String> e = keyStore.aliases();
        PrivateKey kr= null;
        PublicKey ku = null;
        while (e.hasMoreElements()) {
            String alias = (String) e.nextElement();
            if (keyStore.isKeyEntry(alias)) {
                 kr = (PrivateKey) keyStore.getKey(alias, passwd);
                java.security.cert.Certificate cert = keyStore.getCertificate(alias);
                ku = cert.getPublicKey();
            }
        }
    return new KeyPair(ku, kr);
    }
}
