package org.dcsa.ctk.ebl.service;

import jakarta.annotation.PostConstruct;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.stereotype.Service;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CRLReason;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;


@Service
public class CertificateService {
    private KeyStore keyStore;

    @PostConstruct
    public void init() throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        keyStore = KeyStore.getInstance("JKS");
        InputStream inputStream = getClass().getResourceAsStream("/keystore.jks");
        keyStore.load(inputStream, "password".toCharArray());
    }



    public X509Certificate revokeSignatureFromCertificate(X509Certificate certificateToBeRevoked, X509Certificate rootCertificate) throws Exception {
        String alias = keyStore.aliases().nextElement();
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, "password".toCharArray());
        Signature signature = Signature.getInstance("SHA256WithRSAEncryption");
        signature.initSign(privateKey);
        signature.update(rootCertificate.getEncoded());


        // Create a CRL entry for the revoked certificate
        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(org.bouncycastle.asn1.x500.X500Name.getInstance(new X500Name(rootCertificate.getIssuerDN().getName())), rootCertificate.getNotBefore());
        crlBuilder.setNextUpdate(rootCertificate.getNotAfter());

        BigInteger revokedSerial = certificateToBeRevoked.getSerialNumber();
        Date revokedDate = new Date();
        CRLReason reason = CRLReason.PRIVILEGE_WITHDRAWN;

        PrivateKey rootPrivateKey = (PrivateKey) keyStore.getKey(alias, "password".toCharArray());

        crlBuilder.addCRLEntry(revokedSerial, revokedDate, reason.ordinal());

        X509CRL crl = new JcaX509CRLConverter().getCRL(crlBuilder.build(new JcaContentSignerBuilder("SHA256withRSA").build(rootPrivateKey)));

        // Sign the CRL
       // String alias = keyStore.aliases().nextElement();

        //Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(rootPrivateKey);
        signature.update(crl.getEncoded());
        byte[] signatureBytes = signature.sign();

        FileOutputStream fos = new FileOutputStream("revoked_certificates.crl");
        fos.write(crl.getEncoded());
        fos.close();

        return null;
    }

    static public X509v3CertificateBuilder addDistributionList(String crlUri, X509v3CertificateBuilder issuedCertBuilder) {
        GeneralName generalName = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(crlUri));
        GeneralNames generalNames = new GeneralNames(generalName);
        DistributionPointName distPointName = new DistributionPointName(generalNames);
        DistributionPoint distPoint = new DistributionPoint(distPointName, null, generalNames);
        DistributionPoint[] crlDistPoints = new DistributionPoint[] { distPoint };
        CRLDistPoint crlDistPoint = new CRLDistPoint(crlDistPoints);
        try {
            issuedCertBuilder.addExtension(Extension.cRLDistributionPoints, true, crlDistPoint);
        } catch (Exception e) {
            System.out.println("CRL Distribution Point already exist: "+e.getMessage());
        }
        //return crlUri+" is added to the distributionList of x509Certificate";
        return issuedCertBuilder;
    }
/*
    void addAddCRLDistributionPointExtension() throws CertificateException, IOException {
        X509Certificate rootCertificate = null;
        // Load the CRL
        URL crlUrl = new URL("http://example.com/revoked_certificates.crl");
        X509CRL crl = (X509CRL) CertificateFactory.getInstance("X.509").generateCRL(crlUrl.openStream());

        // Add the CRL Distribution Point extension to the root certificate
        GeneralName generalName = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(crlUrl.toString()));
        DistributionPoint distributionPoint = new DistributionPoint(generalName.uniformResourceIdentifier, generalName, null);
        CRLDistributionPointsExtension extension = new CRLDistributionPointsExtension(new DistributionPoint[] { distributionPoint });
        rootCertificate = X509CertImpl.toImpl(rootCertificate);
        rootCertificate.setCritical(extension.getExtensionId().toString(), true);
        rootCertificate.addExtension(extension);

    }


    public X509Certificate generateUnsignedCertificate(X509Certificate signedCertificate) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048, new SecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        X500Name subject = new X500Name(signedCertificate.getSubjectX500Principal().getName());
        BigInteger serialNumber = signedCertificate.getSerialNumber();
        Date notBefore = signedCertificate.getNotBefore();
        Date notAfter = signedCertificate.getNotAfter();

        X509v3CertificateBuilder certificateBuilder = new X509v3CertificateBuilder(subject, serialNumber, notBefore, notAfter, subject, keyPair.getPublic());
        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());

        X509Certificate unsignedCertificate = new JcaX509CertificateConverter().getCertificate(certificateBuilder.build(contentSigner));

        return unsignedCertificate;
    }

    public X509Certificate generateUnsignedCertificate(X509Certificate signedCertificate) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048, new SecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        X500Name subject = new X500Name(signedCertificate.getSubjectX500Principal().getName());
        BigInteger serialNumber = signedCertificate.getSerialNumber();
        Date notBefore = signedCertificate.getNotBefore();
        Date notAfter = signedCertificate.getNotAfter();

        X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(subject, serialNumber, notBefore, notAfter, subject, keyPair.getPublic());

        X509v3CertificateBuilder rootCertBuilder = new JcaX509v3CertificateBuilder(subject, serialNumber, notBefore, notAfter, subject, keyPair.getPublic());

        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());

        X509Certificate unsignedCertificate = new JcaX509CertificateConverter().getCertificate(certificateBuilder.build(contentSigner));

        return unsignedCertificate;
    }
*/

}




