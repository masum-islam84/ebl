package org.dcsa.ctk.ebl.util;

import lombok.extern.java.Log;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.dcsa.ctk.ebl.domain.CertificateManager;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
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
        ContentSigner contentSigner = null;
        try {
            contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).build(certificateManager.getKeyPair().getPrivate());
            certificateManager.setX509Certificate(new JcaX509CertificateConverter().setProvider(bcProvider).getCertificate(certificateManager.getCertBuilder().build(contentSigner)));
            return certificateManager.getX509Certificate();
        }catch (CertificateException  |  OperatorCreationException e) {
            throw new RuntimeException(e.getMessage());
        }
    }

    public static CertificateManager makeCertificateManager(String subjectDN, Date endDate, CertificateManager certificateManager){
        Date startDate = new Date(System.currentTimeMillis());
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
        }
    }

   static public String isCertificateValid(X509Certificate signerCert) {
        StringBuilder validityMsg = new StringBuilder();
        try {
            signerCert.checkValidity();
        } catch (CertificateExpiredException e) {
            validityMsg.append("Error certificate hasexpired")
                    .append(signerCert.getSerialNumber())
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

    public static Date convertDate(long days){
        LocalDateTime localDateTime = LocalDateTime.now().plusDays(days);
        Date date =  java.sql.Timestamp.valueOf(localDateTime);
        return date;
    }



}
