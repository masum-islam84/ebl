package org.dcsa.ctk.ebl.service.impl;

import lombok.extern.java.Log;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.dcsa.ctk.ebl.domain.CertificateInfo;
import org.dcsa.ctk.ebl.domain.enums.CertificateTrust;
import org.dcsa.ctk.ebl.service.X509CertificateManager;
import org.dcsa.ctk.ebl.util.CertificateUtil;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.concurrent.TimeUnit;

@Log
@Service
public class X509CertificateManagerImpl implements X509CertificateManager {

    static public final String ROOT_CERTIFICATE_PASSWORD = "password";
    static public final String ROOT_CERTIFICATE_ALIAS= "root";
    private final String ROOT_CERTIFICATE_ISSUER = "CN=Root CA, O=My Organization, L=My City, ST=My State, C=My Country, emailAddress=rootca@test.com";
    KeyPair rootCertificateKeyPair;

    private X509Certificate rootCertificate;

    private X509Certificate clientCertificate;

    private String clientCommonName;

    private String certificateName;

    private PublicKey publicKey;
    public PublicKey getPublicKey() {
        return publicKey;
    }
    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public void setClientCommonName(String commonName){
        this.clientCommonName = commonName;
    }

    public X509CertificateManagerImpl() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, OperatorCreationException {
        Security.addProvider(new BouncyCastleProvider());
        madeRootCertificateKeyStore();
    }

    public boolean isRootCertificateInitialized(){
        if( rootCertificateKeyPair == null && rootCertificate == null){
            return false;
        }else {
            return true;
        }
    }

    public X509Certificate removeSignature(X509Certificate signedCertificate) throws NoSuchAlgorithmException, OperatorCreationException, CertificateException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        String rootSubject = signedCertificate.getSubjectX500Principal().getName();
        String clientSubject = rootSubject.replace("Root CA", clientCommonName);
        X500Name subject = new X500Name(clientSubject);
        BigInteger serialNumber = signedCertificate.getSerialNumber();
        Date notBefore = signedCertificate.getNotBefore();
        Date notAfter = signedCertificate.getNotAfter();

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(subject, serialNumber, notBefore, notAfter, subject, keyPair.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());
        X509CertificateHolder certHolder = certBuilder.build(signer);
        X509Certificate unSingedCertificate = new JcaX509CertificateConverter().getCertificate(certHolder);
        clientCertificate = unSingedCertificate;
        return clientCertificate;

    }
    private void madeRootCertificateKeyStore() throws NoSuchAlgorithmException, OperatorCreationException, KeyStoreException, CertificateException, IOException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        rootCertificateKeyPair = keyGen.generateKeyPair();

        X500Name x500Name = new X500Name(ROOT_CERTIFICATE_ISSUER);
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + TimeUnit.DAYS.toMillis(365));
        BigInteger serialNumber = BigInteger.valueOf(new SecureRandom().nextLong());


        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(x500Name, serialNumber, notBefore, notAfter, x500Name, rootCertificateKeyPair.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(rootCertificateKeyPair.getPrivate());
        X509CertificateHolder certHolder = certBuilder.build(signer);

        rootCertificate = new JcaX509CertificateConverter().getCertificate(certHolder);
    }

    public ResponseEntity<byte[]> makeClientCertificate(CertificateInfo certificateInfo, CertificateTrust certificateTrust) throws Exception {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.CN, certificateInfo.getCommonName());
        builder.addRDN(BCStyle.OU, certificateInfo.getOrganizationalUnit());
        builder.addRDN(BCStyle.O, certificateInfo.getOrganization());
        builder.addRDN(BCStyle.L, certificateInfo.getLocality());
        builder.addRDN(BCStyle.ST, certificateInfo.getState());
        builder.addRDN(BCStyle.C, certificateInfo.getCountry());
        setClientCommonName(certificateInfo.getCommonName());

        X500Name subject = builder.build();
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();

        X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
                subject,
                BigInteger.valueOf(System.currentTimeMillis()),
                new java.util.Date(certificateInfo.getStartDate().getTime()),
                new java.util.Date(certificateInfo.getEndDate().getTime()),
                subject,
                publicKey
        );

        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(keyPair.getPrivate());
        clientCertificate = new JcaX509CertificateConverter().getCertificate(certificateBuilder.build(signer));

        if(certificateTrust == CertificateTrust.SIGNED){
            clientCertificate = signCertificate(clientCertificate);
            certificateName = "signed-client-certificate.jks";
        }else{
            certificateName = "unsigned-client-certificate.jks";
        }
        return CertificateUtil.getCertificateFile(certificateName, this);
    }
    public ResponseEntity<byte[]> getCertificateFile(String filename){
        certificateName = filename;
        return CertificateUtil.getCertificateFile(certificateName, this);
    }

    public X509Certificate signCertificate(X509Certificate certificate) throws Exception {
        PrivateKey privateKey = rootCertificateKeyPair.getPrivate();
        X500Name issuer = new JcaX509CertificateHolder(rootCertificate).getSubject();
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuer, serial, certificate.getNotBefore(), certificate.getNotAfter(), issuer, certificate.getPublicKey());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(privateKey);
        X509CertificateHolder holder = builder.build(signer);
        X509Certificate signedCertificate = new JcaX509CertificateConverter().getCertificate(holder);
        clientCertificate = signedCertificate;
        return clientCertificate;
    }
    public String isClientCertificateSinged(){
/*        if (clientCertificate.getIssuerX500Principal().equals(rootCertificate.getSubjectX500Principal())) {
            return "The certificate was signed by the root certificate";
        } else {
            return "The certificate was not signed by the root certificate";
        }*/
        try {
            clientCertificate.verify(rootCertificate.getPublicKey());
        } catch (Exception e) {
            return "The certificate was not signed by the root certificate. "+e.getMessage();
        }
        return "The certificate was signed by the root certificate";
    }

    public X509Certificate generateUnsignedCertificate(X509Certificate signedCertificate) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048, new SecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        X500Name subject = new X500Name(signedCertificate.getSubjectX500Principal().getName());
        BigInteger serialNumber = signedCertificate.getSerialNumber();
        Date notBefore = signedCertificate.getNotBefore();
        Date notAfter = signedCertificate.getNotAfter();

        // Initialize a new KeyPair generator
        ContentSigner rootCertContentSigner;
        KeyPair rootKeyPair;
        try {
          //  KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
            keyPairGenerator.initialize(2048);
            rootKeyPair = keyPairGenerator.generateKeyPair();
           // certificateManager.setRootCertKeyPair(rootKeyPair);
            rootCertContentSigner = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(rootKeyPair.getPrivate());
        } catch (OperatorCreationException  e) {
            throw new RuntimeException(e.getMessage());
        }

        X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(subject, serialNumber, notBefore, notAfter, subject, keyPair.getPublic());

       X509v3CertificateBuilder rootCertBuilder = new JcaX509v3CertificateBuilder(subject, serialNumber, notBefore, notAfter, subject, rootKeyPair.getPublic());

        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());

        X509Certificate unsignedCertificate = new JcaX509CertificateConverter().getCertificate(certificateBuilder.build(contentSigner));
        clientCertificate = unsignedCertificate;
        return unsignedCertificate;
    }

    public String addDistributionList(String crlUri) {
        if(!isClientCertificateInitialized()){
            return "certificate is not created yet. Pls make a certificate first";
        }
        GeneralName generalName = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(crlUri));
        GeneralNames generalNames = new GeneralNames(generalName);
        DistributionPointName distPointName = new DistributionPointName(generalNames);
        DistributionPoint distPoint = new DistributionPoint(distPointName, null, generalNames);
        DistributionPoint[] crlDistPoints = new DistributionPoint[] { distPoint };
        CRLDistPoint crlDistPoint = new CRLDistPoint(crlDistPoints);
        try {
          //  certificateManager.getCertBuilder().addExtension(Extension.cRLDistributionPoints, true, crlDistPoint);
          //  CertificateUtil.getSelfSignCertificate(certificateManager);
        } catch (Exception e) {
            return "CRL Distribution Point already exist: "+e.getMessage();
        }
        return crlUri+" is added to the distributionList of x509Certificate";
    }

    public String removeDistributionList(String crlUri) {
        if(!isClientCertificateInitialized()){
            return "certificate is not created yet. Pls make a certificate first";
        }
        //certificateManager.getCertBuilder().removeExtension(Extension.cRLDistributionPoints);
       // CertificateUtil.getSelfSignCertificate(certificateManager);

/*        GeneralName generalName = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(crlUri));
        GeneralNames generalNames = new GeneralNames(generalName);
        DistributionPointName distPointName = new DistributionPointName(generalNames);
        DistributionPoint distPoint = new DistributionPoint(distPointName, null, generalNames);
        DistributionPoint[] crlDistPoints = new DistributionPoint[] { distPoint };
        CRLDistPoint crlDistPoint = new CRLDistPoint(crlDistPoints);
        try {
            certificateManager.getCertBuilder().addExtension(Extension.cRLDistributionPoints, true, crlDistPoint);
            CertificateUtil.getSelfSignCertificate(certificateManager);
        } catch (CertIOException e) {
            throw new RuntimeException(e.getMessage());
        }*/
        return crlUri+" is removed from distributionList of x509Certificate";
    }

    public String getDistributionList(){
        return  "";
    }

    public  X509Certificate     getClientCertificate(){
        return clientCertificate;
    }

    public void setClientCertificate(X509Certificate certificate){
        clientCertificate = certificate;
    }

    public  boolean isClientCertificateInitialized(){
        if( clientCertificate == null && !certificateName.isEmpty() ){
            return false;
        }else{
            return true;
        }
    }

    public String isClientCertificateValid(){
        if(!isRootCertificateInitialized()){
            return "certificate is not created yet. Pls make a certificate first";
        }
        return CertificateUtil.isCertificateValid(clientCertificate);
    }
    public String getCertificateStr(){
        if(!isClientCertificateInitialized()){
            return "certificate is not created yet. Pls make a certificate first";
        }
        StringWriter sw = new StringWriter();
        try (JcaPEMWriter jpw = new JcaPEMWriter(sw)) {
            jpw.writeObject(clientCertificate);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return sw.toString();
    }

}