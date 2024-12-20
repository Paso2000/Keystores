package controller;

import model.*;
import view.View;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;

/**
 * Controller class for managing the interaction between the View and the Model.
 * This class implements the MVC design pattern, serving as the Controller.
 * It handles user actions in the GUI (View) and interacts with the business logic in the Model.
 */
public class PBEController {

    private PBEAlgorithm pbeAlgorithm = new PBEAlgorithm();
    private PBEAlgorithmFile pbeAlgorithmFile = new PBEAlgorithmFile();
    private HashAlgorithmFile hashAlgorithmFile = new HashAlgorithmFile();
    private HashAlgorithm hashAlgorithm = new HashAlgorithm();
    private KeyMenagement keyMenagement = new KeyMenagement();

    private DigitalSignAlgorithm digitalSignAlgorithm = new DigitalSignAlgorithm();
    private PublicKeyAlgorithm publicKeyAlgorithm = new PublicKeyAlgorithm();
    private View view;
    private String result;

    private String[] emptyArrray= {};

    private String value;

    private PublicKey publicKey;

    private PrivateKey privateKey;

    private KeyStores keyStores = new KeyStores();

    private KeyStoreMenager keyStoreMenager;



    /**
     * Constructor for PBEController.
     *
     * @param view              The GUI (View) used to interact with the user.
     */
    public PBEController(View view) {
        this.view = view;

        // Connect action listeners to the buttons in the View
        this.view.addEncryptButtonListener(new EncryptButtonListener());
        this.view.addDecryptButtonListener(new DecryptButtonListener());
        this.view.addFileHashButtonListener(new FileHashButtonListener());
        this.view.addVerifyFileHashButtonListener(new VerifyFileHashButtonListener());
        this.view.addGenerateKeyButtonListener(new GenerateKeyButtonListener());
        this.view.addLoadKeyButtonListener(new LoadKeyButtonListener());
        this.view.addShowKeyButtonListener(new ShowKeyButtonListener());
        this.view.addDigitalSignButtonListener(new DigitalSignButtonListener());
        this.view.addVerifyDigitalSignButtonListener(new VerifyDigitalSignButtonListener());
        this.view.addPublicKeyEncryptButtonListener(new PublicKeyEncryptButtonListener());
        this.view.addPublicKeyDencryptButtonListener(new PublicKeyDencryptButtonListener());
        this.view.addSaveKeyButtonListener(new SaveKeyButtonListener());
        this.view.addStorageKeyButtonListener(new StorageKeyButtonListener());
        this.view.addLoadStorageKeyButtonListener(new LoadStorageKeyButtonListener());
        this.view.addCreateStorageKeyButtonListener(new CreateStorageKeyButtonListener());
        this.view.addVisualizeStorageKeyButtonListener(new VisualizeStorageKeyButtonListener());
        this.view.addCreateKeyAndCertificateButtonListener(new CreateKeyAndCertificateButtonListener());
        //this.view.addImportKeyButtonListener(new ImportKeyButtonListener());
        //this.view.addDeleteStorageKeyButtonListener(new DeleteStorageKeyButtonListener());

    }

    class CreateStorageKeyButtonListener implements ActionListener{

        @Override
        public void actionPerformed(ActionEvent e) {
           char[] passwd= view.getKeyStorePasswd();
            try {
                keyStoreMenager = new KeyStoreMenager("myStore.jks",passwd);
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
        }
    }

    class VisualizeStorageKeyButtonListener implements ActionListener{

        @Override
        public void actionPerformed(ActionEvent e) {
            try {
                char[] passwd= view.getKeyStorePasswd();
                Map<String,KeyPair> entries = keyStoreMenager.listEntries(passwd);
                for (Map.Entry<String, KeyPair> entry : entries.entrySet()) {
                    System.out.println();
                    view.addResult("\n"+ "Alias: " + entry.getKey() + "Public Key: " + entry.getValue().getPublic()+ "Private Key: "+entry.getValue().getPrivate());
                }
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
        }
    }

    class CreateKeyAndCertificateButtonListener implements ActionListener{

        @Override
        public void actionPerformed(ActionEvent e) {
            char[] passwd= view.getKeyStorePasswd();

            try {
                keyStoreMenager.createAndStoreKeyPair( "marco",passwd);
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
        }
    }


    class LoadStorageKeyButtonListener implements ActionListener{

        @Override
        public void actionPerformed(ActionEvent e) {
            char[] passwd = view.getKeyStorePasswd();
            try {
                KeyPair keyPair =keyStores.getKeyFromStorage(passwd);
                privateKey = keyPair.getPrivate();
                publicKey = keyPair.getPublic();
                view.addResult(privateKey.toString()+"\n\n"+ publicKey.toString());
            } catch (KeyStoreException | UnrecoverableKeyException | NoSuchAlgorithmException |ClassCastException ex) {
                view.addResult("\nKey store not initialized or wrong Password");
            }
        }
    }



    class StorageKeyButtonListener implements ActionListener{

        @Override
        public void actionPerformed(ActionEvent e) {
            char[] passwd = view.getKeyStorePasswd();
            String keyStorageName = view.getKeyStorgeName();
            try {
                keyStores.KeyStoring(keyStorageName,passwd);
            } catch (KeyStoreException | IOException | CertificateException | NoSuchAlgorithmException ex) {
                view.addResult("\nKey store path or Password wrong");
            }
        }
    }
    class PublicKeyEncryptButtonListener implements  ActionListener{

        @Override
        public void actionPerformed(ActionEvent e) {
            File file = View.getFile();
            if(publicKey!=null && file!=null) {
                String inputFilePath = file.getAbsolutePath();
                String outputFilePath = System.getProperty("user.home") + "/Desktop/test_encrypted.ENC";
                String algorithmName = view.getPublicKeyAlgorithm();
                try {
                    publicKeyAlgorithm.encryptFile(inputFilePath, outputFilePath, publicKey, algorithmName);
                    view.addResult("\nCrypted with succesfully [" + outputFilePath +"]");
                } catch (Exception ex) {
                    throw new RuntimeException(ex);
                }
            }else view.addResult("\nPrivate key not loaded or file not choose");
        }
    }

    /**
     * Listener for the "Decrypt with Private Key" button.
     * Handles file decryption operations using a private key.
     */
    class PublicKeyDencryptButtonListener implements ActionListener{

        @Override
        public void actionPerformed(ActionEvent e) {
            File file = View.getFile();
            String outputFilePath = System.getProperty("user.home") + "/Desktop/test_decrypted.DEC";
            String algorithmName = view.getPublicKeyAlgorithm();
            if(privateKey!=null && file!=null) {
                try {
                    String inputFilePath = file.getAbsolutePath();
                  boolean isVerified =  publicKeyAlgorithm.decryptFile(inputFilePath, outputFilePath, privateKey, algorithmName);
                  if (isVerified)
                    view.addResult("\nDecrypted with succesfully [" + outputFilePath +"]");
                  else
                      view.addResult("\nThis File can't be deciphered");
                } catch (Exception ex) {
                    view.addResult("Try again something went wrong");
                }
            }else view.addResult("\nPrivate key not loaded or file not choose");
        }
    }

    /**
     * Listener for the "Sign File" button.
     * Handles file signing operations.
     */

    class DigitalSignButtonListener implements  ActionListener{
        @Override
        public void actionPerformed(ActionEvent e) {
            String SignAlg = view.getSignAlgorithm();
            File file = View.getFile();
            if(privateKey!=null && file!=null) {
                try {
                    String[] result = digitalSignAlgorithm.Sign(file, SignAlg, privateKey);
                    view.addResult("\nFile signed at Path: "+ result[1]+"\nWith this calculated sign: "+ result[0]);
                } catch (Exception ex) {
                    throw new RuntimeException(ex);
                }
            }else view.addResult("\nPrivate key not loaded or file not choose");

        }
    }
    /**
     * Listener for the "Verify File Signature" button.
     * Handles signature verification for files.
     */
    class VerifyDigitalSignButtonListener implements  ActionListener{
        @Override
        public void actionPerformed(ActionEvent e) {
            String SignAlg = view.getSignAlgorithm();
            File file = View.getFile();
            if(publicKey!=null && file!=null) {
                try {
                    String[] result  = digitalSignAlgorithm.Verify(file, SignAlg, publicKey);
                    if (result!=null){
                        view.addResult("\nCorrisponding sign, file not modified\n Verified file Path: "+ result[1] + "\nPrevious hash: "+result[0]);
                    }else{
                       view.addResult("\nVerification failed, file modified or wrong public key");
                    }
                } catch (Exception ex) {
                    view.addResult("\nVerification failed, file modified or wrong public key");
                }
            }else view.addResult("\nPublic key not loaded or file not choose");

        }
        }

    /**
     * Listener for the "Show Key" button.
     * Displays the currently loaded public and private keys in the view.
     * If no keys are loaded, an appropriate message is shown.
     */
    class ShowKeyButtonListener implements ActionListener{

        @Override
        public void actionPerformed(ActionEvent e) {
            if(publicKey!=null && privateKey!=null){
                view.addResult(publicKey.toString());
                view.addResult(privateKey.toString());
            }else view.addResult("\nNo key loaded");
        }
    }
    /**
     * Listener for the "Generate Key" button.
     * Generates a new public-private key pair and stores them in the controller.
     * If the key generation fails, a runtime exception is thrown.
     */
    class GenerateKeyButtonListener implements ActionListener{
        @Override
        public void actionPerformed(ActionEvent e) {
            try {
                KeyPair keyPair = keyMenagement.keyGeneration();
                publicKey = keyPair.getPublic();
                privateKey = keyPair.getPrivate();
            } catch (NoSuchAlgorithmException ex) {
                throw new RuntimeException(ex);
            }
            view.addResult("\nKey generate successfully");
        }
    }

    /**
     * Listener for the "Save Key" button.
     * Saves the current public and private keys to the specified file path.
     * If the keys are not generated or the file path is invalid, a message is shown in the view.
     */

    class SaveKeyButtonListener implements ActionListener{

        @Override
        public void actionPerformed(ActionEvent e) {
            String keyStoragePath = view.getKeyStoragePath();
            if (publicKey != null && privateKey != null && Files.exists(Path.of(keyStoragePath)) && Files.isRegularFile(Path.of(keyStoragePath))) {
                keyMenagement.keyStorage(keyStoragePath, publicKey, privateKey);
                view.addResult("\nKey saved successfully");
            }
            else view.setResult("\nKey not generated yet or Saving file path not correct");
        }
    }

    /**
     * Listener for the "Load Key" button.
     * Loads a public-private key pair from the specified file path.
     * If the keys cannot be loaded due to an error (e.g., file not found or incorrect password), a message is shown.
     */

    class LoadKeyButtonListener implements ActionListener{
        @Override
        public void actionPerformed(ActionEvent e) {
            String keyStoragePath = view.getKeyStoragePath();
            value = view.getPasswordValue();
            KeyPair keys = null;
            try {
                keys = keyMenagement.keyLoad(keyStoragePath,value);
            } catch (IOException | InvalidKeySpecException | NoSuchAlgorithmException | ClassNotFoundException ex) {
                view.addResult("Key can't be loaded");
            }
            publicKey = keys.getPublic();
            privateKey = keys.getPrivate();
            view.addResult("\nKeys loaded");
        }
    }

    /**
     * Listener for the "Hash File" button.
     * Hashes the selected file using the specified hash algorithm and an optional password.
     * The hash result, algorithm used, and file size are displayed in the view.
     * If no file is selected or no value is provided, an error message is shown.
     */

    class FileHashButtonListener implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            //Value control
            value = view.getPasswordValue();
            if(!value.isEmpty()){
            File file = View.getFile();
            //File control
            if (file != null) {
                String hashFunction = view.getHashAlgorithm();
                try {
                    String[] result = hashAlgorithmFile.hashFileEncrypt(file, hashFunction, value);
                    view.addResult("File hash: " + result[0] +
                            "\nWith the Algorithm: " + result[1]
                            + "\nSize: " + file.length());
                } catch (Exception ex) {
                    throw new RuntimeException(ex);
                }
            } else {
                view.addResult("No file selected");
            }
        }else {
                view.addResult("Insert a Value");
            }
    }}

    /**
     * Listener for the "Verify File Hash" button.
     * Handles file hash verification operations.
     */
    class VerifyFileHashButtonListener implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            value = view.getPasswordValue();
            if(!value.isEmpty()){
            File file = View.getFile();
            if (file != null) {
                String hashFunction = view.getHashAlgorithm();
                try {
                    String[] result = hashAlgorithmFile.hashVerifyFile(file, hashFunction, value);
                    if (result[0].equals(result[1])) {
                        view.addResult("File hash: " + result[0] + "\nCalculated hash: " + result[1] +
                                "\nSize: " + file.length() +
                                "\nNot modified file, the hash is the same");
                    } else {
                        view.addResult("File hash: " + result[0] + "\nCalculated hash: " + result[1] +
                                "\nSize: " + file.length() +
                                "\nModified file or different password");
                    }
                } catch (Exception ex) {
                    throw new RuntimeException(ex);
                }
            } else {
                view.addResult("No file selected");
            }}else {
                view.addResult("Insert a Value");
            }
        }
    }

    /**
     * Listener for the "Hash Message" button.
     * Handles hashing operations for plaintext messages.
     */
    class MessageHashButtonListener implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            value = view.getPasswordValue();
            if(!value.isEmpty()){
            String plaintext = view.getInputText();
            String hashFunction = view.getHashAlgorithm();
            try {
                result = hashAlgorithm.protectMessageHash(plaintext, hashFunction, value);
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
            view.setResult(result);
        }else{
            view.setResult("Insert a value");
        }
    }
    }

    /**
     * Listener for the "Verify Message Hash" button.
     * Handles hash verification for messages.
     */
    class VerifyButtonListener implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            value = view.getPasswordValue();
            if(!value.isEmpty()){
            String hashedTest = view.getInputText();
            String hashFunction = view.getHashAlgorithm();
            try {
                result = hashAlgorithm.verifyHashMessage(hashedTest, hashFunction, value);
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
            view.setResult(result);
        }else {
                view.setResult("Insert a value");
            }
    }}

    /**
     * Listener for the "Encrypt File" button.
     * Handles file encryption operations.
     */
    class EncryptButtonListener implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            try {
                File file = View.getFile();
                String password = view.getPasswordValue();
                String symmetricAlgorithm = view.getSymmetricAlgorithm();
                pbeAlgorithmFile.Encrypt(file, password, symmetricAlgorithm);
                view.addResult("Successfully encrypted file: " + file.getPath() +
                        "\nSize: " + file.length() + " byte");
            } catch (Exception ex) {
                view.showError("Error during encryption: " + ex.getMessage());
            }
        }
    }

    /**
     * Listener for the "Decrypt File" button.
     * Handles file decryption operations.
     */
    class DecryptButtonListener implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            try {
                File file = View.getFile();
                if (file != null) {
                    String password = view.getPasswordValue();
                    String symmetricAlgorithm = view.getSymmetricAlgorithm();
                    pbeAlgorithmFile.Decrypt(file, password, symmetricAlgorithm);
                    view.addResult("Successfully decrypted file: " + file.getPath() +
                            "\nSize: " + file.length() + " byte");
                } else {
                    view.addResult("No file selected");
                }
            } catch (Exception ex) {
                view.showError("Error during decryption: " + ex.getMessage());
            }
        }
    }
}