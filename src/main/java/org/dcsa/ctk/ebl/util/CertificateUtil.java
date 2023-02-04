package org.dcsa.ctk.ebl.util;

import lombok.extern.java.Log;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.dcsa.ctk.ebl.domain.CertificateInfo;
import org.dcsa.ctk.ebl.domain.CertificateManager;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.util.Calendar;
import java.util.Date;
@Log
public class CertificateUtil {
    public static KeyPair getKeyPair(){
        KeyPairGenerator keyPairGenerator; // Key pair generator
        KeyPair keypair; // Key pair
        try {
            keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(571, new SecureRandom());
            keypair = keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e.getMessage());
        }
        return keypair;
    }

    public static X509Certificate getSelfSignCertificate(CertificateManager certificateManager){
        Provider bcProvider = new BouncyCastleProvider();
        Security.addProvider(bcProvider);
        String signatureAlgorithm = "SHA256WithRSA"; // <-- Use appropriate signature algorithm based on your keyPair algorithm.
        ContentSigner contentSigner;
        try {
            contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).build(certificateManager.getRootCertKeyPair().getPrivate());
            certificateManager.setClientCertificate(new JcaX509CertificateConverter().setProvider(bcProvider).getCertificate(certificateManager.getCertificateBuilder().build(contentSigner)));
            return certificateManager.getClientCertificate();
        }catch (CertificateException  |  OperatorCreationException e) {
            throw new RuntimeException(e.getMessage());
        }
    }

    public static CertificateManager makeCertificateManager(CertificateInfo certificateInfo, CertificateManager certificateManager) throws NoSuchAlgorithmException, OperatorCreationException, CertificateException {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.CN, certificateInfo.getCommonName());
        builder.addRDN(BCStyle.OU, certificateInfo.getOrganizationalUnit());
        builder.addRDN(BCStyle.O, certificateInfo.getOrganization());
        builder.addRDN(BCStyle.L, certificateInfo.getLocality());
        builder.addRDN(BCStyle.ST, certificateInfo.getState());
        builder.addRDN(BCStyle.C, certificateInfo.getCountry());

        X500Name subject = builder.build();
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();

        X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
                subject,
                BigInteger.valueOf(System.currentTimeMillis()),
                new java.util.Date(certificateInfo.getStartDate().getTime()),
                new java.util.Date(certificateInfo.getEndDate().getTime()),
                subject,
                keyPair.getPublic()
        );

        certificateManager.setCertificateBuilder(certificateBuilder);
        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(keyPair.getPrivate());
        X509Certificate clientCertificate = new JcaX509CertificateConverter().getCertificate(certificateBuilder.build(signer));
        certificateManager.setClientCertificate(clientCertificate);
        return certificateManager;




/*        Date startDate = new Date(System.currentTimeMillis());
        X500Name dnName = new X500Name(subjectDN);
        BigInteger certSerialNumber = new BigInteger(Long.toString(System.currentTimeMillis())); // <-- Using the current timestamp as the certificate serial number
        KeyPair keyPair = CertificateUtil.getKeyPair();
        certificateManager.setKeyPair(keyPair);
        try {
            JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(dnName, certSerialNumber, startDate, endDate, dnName, keyPair.getPublic());
            // Basic Constraint
            BasicConstraints basicConstraints = new BasicConstraints(true); // <-- true for CA, false for EndEntity
            certBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.19"), true, basicConstraints); // Basic Constraints is usually marked as critical.
            certificateManager.setCertBuilder(certBuilder);
            return certificateManager;
        }catch (IOException e) {
            throw new RuntimeException(e.getMessage());
        }*/
    }

   static public String isCertificateValid(X509Certificate signerCert) {
        StringBuilder validityMsg = new StringBuilder();
        try {
            signerCert.checkValidity();
        } catch (CertificateExpiredException e) {
            validityMsg.append("Error certificate has expired: ")
                    .append(signerCert.getNotAfter())
                    .append("\n")
                    .append(" getIssuerDN ")
                    .append(signerCert.getIssuerDN());
            System.out.print(validityMsg);
            return validityMsg.toString();
        } catch (CertificateNotYetValidException e) {
            System.out.println("ocsp.errornotyetvalid: "+signerCert.getSerialNumber()+" getIssuerDN: "+
                    signerCert.getIssuerDN());
            validityMsg.append("ocsp.errornotyetvalid: ")
                       .append(signerCert.getSerialNumber())
                       .append(" getIssuerDN: ")
                        .append(signerCert.getIssuerDN());
            return "false";
        }
        validityMsg.append("The certificate is valid");
        return validityMsg.toString();
    }

    static public KeyPair createKeypair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    private static JcaX509v3CertificateBuilder createRootCert(KeyPair keypair) throws Exception {
        X500NameBuilder ib = new X500NameBuilder(RFC4519Style.INSTANCE);
        ib.addRDN(RFC4519Style.c, "AQ");
        ib.addRDN(RFC4519Style.o, "Test");
        ib.addRDN(RFC4519Style.l, "Vostok Station");
        ib.addRDN(PKCSObjectIdentifiers.pkcs_9_at_emailAddress, "test@vostok.aq");
        X500Name issuer = ib.build();
        return createCert(keypair, issuer, issuer);
    }

    static JcaX509v3CertificateBuilder createCert(KeyPair keyPair,
                                                  X500Name issuer,
                                                  X500Name subject) {
        Calendar calendar = Calendar.getInstance();
        Date fromTime = calendar.getTime();
        calendar.add(Calendar.YEAR, 5);
        return new JcaX509v3CertificateBuilder(
                issuer,
                BigInteger.valueOf(System.currentTimeMillis()),
                fromTime,
                calendar.getTime(),
                subject,
                keyPair.getPublic()
        );
    }
/*
    static public void constructCert() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
       //((Logger)LoggerFactory.getLogger(CertificateGenerator.class)).setLevel(Level.DEBUG);
        File file = new File( File.separator+"dm-agent.jks");//Files.createTempFile("dm-agent", ".jks");

        KeyPair keypair = createKeypair();
        JcaX509v3CertificateBuilder cb = createRootCert(keypair);
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(keypair.getPrivate());
        X509CertificateHolder rootCert = cb.build(signer);
        KeystoreConfig cert = CertificateGenerator.constructCert(rootCert,
                keypair.getPrivate(),
                file,
                ImmutableSet.of("test1", "test2"));
        assertNotNull(cert);
    }

    static KeystoreConfig constructCert(X509CertificateHolder rootCert, PrivateKey rootKey, File keystoreFile, Set<String> names) throws Exception {
        log.debug("Create certificate in {} keystore for names: {}", keystoreFile.getAbsolutePath(), names);
        KeystoreConfig.Builder cb = KeystoreConfig.builder();
        // verify: keytool -list -keystore dm-agent.jks
        KeyStore ks = KeyStore.Builder.newInstance("JKS", null, new KeyStore.PasswordProtection(null)).getKeyStore();
        Certificate jceRootCert = toJava(rootCert);
        // we use simple password, because no way to safe store password, and so complexity of password does nothing
        String keypass = "123456";
        String kspass = "123456";
        KeyPair keyPair = createKeypair();
        X509CertificateHolder serverCert = createServerCert(rootKey, rootCert, keyPair, names);
        Certificate jceServerCert = toJava(serverCert);
        ks.setKeyEntry("key", keyPair.getPrivate(), keypass.toCharArray(), new Certificate[]{jceServerCert, jceRootCert});
        cb.keystorePassword(kspass);
        cb.keyPassword(keypass);
        try(FileOutputStream fos = new FileOutputStream(keystoreFile)) {
            ks.store(fos, kspass.toCharArray());
        }
        cb.keystore(keystoreFile);
        return cb.build();
    }
*/

    public static Date convertDate(long days){
        LocalDateTime localDateTime = LocalDateTime.now().plusDays(days);
        Date date =  java.sql.Timestamp.valueOf(localDateTime);
        return date;
    }
}
