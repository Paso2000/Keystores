package model;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Date;

public class SelfSignedCertificateGenerator{

    static {
        // Add Bouncy Castle as a security provider
        Security.addProvider(new BouncyCastleProvider());
    }

    public static X509Certificate generateCertificate(KeyPair keyPair, String dn, int days) throws Exception {
        // Set validity dates
        Date startDate = new Date();
        Date endDate = new Date(startDate.getTime() + days * 24L * 60 * 60 * 1000); // days to milliseconds

        // Generate a random serial number
        BigInteger serialNumber = new BigInteger(64, new SecureRandom());

        // Use X500Name for the Distinguished Name
        X500Name subject = new X500Name(dn);

        // Create the certificate builder
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                subject,          // Issuer (self-signed)
                serialNumber,     // Serial number
                startDate,        // Start date
                endDate,          // End date
                subject,          // Subject (same as issuer)
                keyPair.getPublic() // Public key
        );

        // Create the content signer using SHA256withRSA
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC") // Specify Bouncy Castle
                .build(keyPair.getPrivate());

        // Build the certificate
        X509CertificateHolder certHolder = certBuilder.build(signer);

        // Convert to JCA X509Certificate
        return new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(certHolder);
    }
}


