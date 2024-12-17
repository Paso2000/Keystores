package view;
import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.File;

public class View extends JFrame{
    private File selectedFile;
    private JTextArea textArea = new JTextArea();
    private JComboBox<String> comboCipher;
    private JComboBox<String> comboHash;
    private JMenuItem cipher;
    private JMenuItem decipher;
    private JMenuItem protegerFileWithHash;
    private JMenuItem verificarFileHash;

    private JMenuItem publicKeyEncryption;

    private JMenuItem publicKEyDecryption;

    private JMenuItem digitalSign;

    private JMenuItem keySave;

    private JMenuItem verifyDigitalSign;

    private JMenuItem Exit;
    private JPanel passwordPanel;
    private JLabel passwordLabel;
    private JPasswordField passwordField;
    private JLabel labelCipher;
    private JLabel labelHash;
    private JLabel labelSign;
    private JComboBox<String> comboSign;
    private JLabel labelPublicKey;
    private JComboBox<String> comboPublicKey;
    private JLabel labelFilePath;
    private JTextField pathField;
    private File keyStorage;

    private JMenuItem keyGenerate;

    private JMenuItem keyLoad;

    private JMenuItem printKey;






    public View() {
        // Crea il frame
        JFrame frame = new JFrame("Practice 4 of SRT");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(600, 400);

        // Crea la barra dei menu
        JMenuBar menuBar = new JMenuBar();


        // Crea il menu
        JMenu menuFile = new JMenu("File");
        JMenu menuKey = new JMenu("Key");

        menuBar.add(menuFile);
        menuBar.add(menuKey);


        // Crea le voci di menu
        cipher = new JMenuItem("Cipher");
        cipher.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_C, ActionEvent.CTRL_MASK));

        decipher = new JMenuItem("Decipher");
        decipher.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_D, ActionEvent.CTRL_MASK));

        protegerFileWithHash = new JMenuItem("Protect with hash");
        protegerFileWithHash.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_H, ActionEvent.CTRL_MASK));


        verificarFileHash = new JMenuItem("Verify hash");
        verificarFileHash.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_V, ActionEvent.CTRL_MASK));

        digitalSign = new JMenuItem("DigitalSign");
        verifyDigitalSign = new JMenuItem("Verify DigitalSign");

        publicKeyEncryption = new JMenuItem("Public Key Encryption");
        publicKEyDecryption = new JMenuItem("Public Key Decryption");




        Exit = new JMenuItem("Exit");
        Exit.addActionListener(e -> System.exit(0));

        // Aggiungi le voci di menu al menu "Fichero"
        menuFile.add(cipher);
        menuFile.add(decipher);
        menuFile.add(protegerFileWithHash);
        menuFile.add(verificarFileHash);
        menuFile.add(digitalSign);
        menuFile.add(verifyDigitalSign);
        menuFile.add(publicKeyEncryption);
        menuFile.add(publicKEyDecryption);

        menuFile.addSeparator(); // Aggiunge una linea di separazione
        menuFile.add(Exit);

        labelCipher = new JLabel("Algorithm Cipher");
        comboCipher = new JComboBox<>(new String[] {
                "PBEWithMD5AndDES", "PBEWithMD5AndTripleDES", "PBEWithSHA1AndDESede", "PBEWithSHA1AndRC2_40"
        });
        comboCipher.setSelectedItem("PBEWithMD5AndDES");


        // Componenti per Algoritmo Hash/HMac
        labelHash = new JLabel("Algorithm Hash/HMac");
        comboHash = new JComboBox<>(new String[] {
                "MD2", "MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512",
                "HmacMD5", "HmacSHA1", "HmacSHA256", "HmacSHA384", "HmacSHA512"
        });
        comboHash.setSelectedItem("MD2");

        labelSign = new JLabel("Sign Algorithm");
        comboSign = new JComboBox<>(new String[]{"SHA1withRSA", "MD2withRSA", "MD5withRSA",
                "SHA224withRSA", "SHA256withRSA", "SHA384withRSA","SHA512withRSA"});
        comboSign.setSelectedItem("SHA1withRSA");

        labelPublicKey = new JLabel("Public Key Algorithm");
        comboPublicKey = new JComboBox<>(new String[]{"RSA/ECB/PKCS1Padding"});
        comboPublicKey.setSelectedItem("RSA/ECB/PKCS1Padding");
        labelFilePath = new JLabel("File path for saving key");
        pathField = new JTextField("C:\\Users\\lucap\\Desktop\\pratica4.txt",100);

       JButton FileButton = new JButton("Choose File");
       FileButton.addActionListener(new ActionListener() {
           @Override
           public void actionPerformed(ActionEvent e) {
               keyStorage= getFile();
               assert keyStorage != null;
               pathField.setText(keyStorage.getAbsolutePath());
           }
       });





        JMenuItem algorithm = new JMenuItem("Algorithm");
        algorithm.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                // Crea e mostra il dialogo di configurazione
                JDialog dialog = new JDialog(frame, "Key Option", true);
                dialog.setLayout(new GridLayout(6, 2, 10, 10));
                dialog.setSize(500, 200);
                dialog.setLocationRelativeTo(frame);

                dialog.add(labelCipher);
                dialog.add(comboCipher);
                dialog.add(labelHash);
                dialog.add(comboHash);
                dialog.add(labelSign);
                dialog.add(comboSign);
                dialog.add(labelPublicKey);
                dialog.add(comboPublicKey);
                dialog.add(labelFilePath);
                dialog.add(FileButton);
                dialog.add(pathField);
                dialog.setVisible(true);
            }
        });
        menuKey.add(algorithm);
        keyGenerate = new JMenuItem("Generate Keys");
        keySave = new JMenuItem("Save keys in the file");
        keyLoad = new JMenuItem("Load key from the file");
        printKey = new JMenuItem("Show the keys");
        menuKey.add(keyGenerate);
        menuKey.add(keySave);
        menuKey.add(keyLoad);
        menuKey.add(printKey);

        passwordPanel = new JPanel(new BorderLayout());
        passwordLabel = new JLabel("Value: ");
        passwordField = new JPasswordField(20);
        passwordPanel.add(passwordLabel, BorderLayout.WEST);
        passwordPanel.add(passwordField, BorderLayout.CENTER);

        textArea.setLineWrap(true); // Permette l'andata a capo automatica
        textArea.setWrapStyleWord(true); // Andata a capo sui confini delle parole

        // Aggiungi la JTextArea a uno JScrollPane per abilitarne lo scorrimento

        JScrollPane scrollPane = new JScrollPane(textArea);
        frame.setLayout(new BorderLayout());
        frame.setJMenuBar(menuBar);
        frame.add(passwordPanel, BorderLayout.NORTH);
        frame.add(scrollPane, BorderLayout.CENTER);
        frame.setVisible(true);


    }
    public String getInputText() {
        return textArea.getText();
    }

    public String getPasswordValue() {
        System.out.println(new String(passwordField.getPassword()));
        return new String(passwordField.getPassword());
    }

    public String getSymmetricAlgorithm() {
        return (String) comboCipher.getSelectedItem();}

    public String getPublicKeyAlgorithm() {
        return (String) comboPublicKey.getSelectedItem();}

    public String getSignAlgorithm() {
        return (String) comboSign.getSelectedItem();}

    public String getKeyStoragePath() {
        return pathField.getText();}

    public String getHashAlgorithm(){return (String) comboHash.getSelectedItem(); }


    // Methods to view output
    public void addResult(String result) {
        textArea.append(result+"\n\n");
    }
    public void setResult(String result) {
        textArea.setText(result);
    }
    // button listener
    public void addEncryptButtonListener(ActionListener listener) {
        cipher.addActionListener(listener);
    }

    public void addDecryptButtonListener(ActionListener listener) {
        decipher.addActionListener(listener);
    }

    public void addFileHashButtonListener(ActionListener listener) {
        protegerFileWithHash.addActionListener(listener);
    }
    public void addVerifyFileHashButtonListener(ActionListener listener) {
        verificarFileHash.addActionListener(listener);
    }
    public void addDigitalSignButtonListener(ActionListener listener) {
        digitalSign.addActionListener(listener);
    }
    public void addVerifyDigitalSignButtonListener(ActionListener listener) {
        verifyDigitalSign.addActionListener(listener);
    }

    public void addPublicKeyEncryptButtonListener(ActionListener listener) {
        publicKeyEncryption.addActionListener(listener);
    }
    public void addPublicKeyDencryptButtonListener(ActionListener listener) {
        publicKEyDecryption.addActionListener(listener);
    }

    public void addGenerateKeyButtonListener(ActionListener listener) {
        keyGenerate.addActionListener(listener);
    }

    public void addLoadKeyButtonListener(ActionListener listener) {
        keyLoad.addActionListener(listener);
    }

    public void addShowKeyButtonListener(ActionListener listener) {
        printKey.addActionListener(listener);
    }

    public void addSaveKeyButtonListener(ActionListener listener) {
        keySave.addActionListener(listener);
    }


    // Methods to view error message
    public void showError(String errorMessage) {
        JOptionPane.showMessageDialog(this, errorMessage);
    }
    public static File getFile() {
        // Crea un JFileChooser
        JFileChooser fileChooser = new JFileChooser();

        // Mostra il dialogo di selezione file
        int returnValue = fileChooser.showOpenDialog(null);

        // Verifica l'azione dell'utente
        if (returnValue == JFileChooser.APPROVE_OPTION) {
            // Restituisci il file selezionato
            return fileChooser.getSelectedFile();
        }

        // Nessun file selezionato
        return null;
    }
}