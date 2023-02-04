package org.dcsa.ctk.ebl.service.impl;

import lombok.extern.java.Log;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.dcsa.ctk.ebl.domain.CertificateInfo;
import org.dcsa.ctk.ebl.domain.CertificateManager;
import org.dcsa.ctk.ebl.service.X509CertificateManager;
import org.dcsa.ctk.ebl.util.CertificateUtil;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;

import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.Objects;
import java.util.logging.Level;

@Log
@Service
public class X509CertificateManagerImpl implements X509CertificateManager {

    static public final String ROOT_CERTIFICATE = "rootCA.crt";
    static public final String ROOT_PRIVATE_KEY = "rootCA.key";
    static public final String ROOT_JAVA_KEY_STORE = "rootCA.jks";
    static public final String ROOT_CERTIFICATE_PASSWORD = "password";
    static public final String ROOT_CERTIFICATE_ALIAS= "root";
    private CertificateManager certificateManager;
    public CertificateManager getCertificateManager() {
        return certificateManager;
    }
    public X509CertificateManagerImpl(){
        certificateManager = new CertificateManager();
      //  loadRootCertAndPrivateKey();
       // loadRootCertAndPrivateKey2();
        makeRootCertificate();
    }

    private void makeRootCertificate() {
        // Add the BouncyCastle Provider
        Security.addProvider(new BouncyCastleProvider());

        // Setup start date to yesterday and end date for 1 year validity
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.DATE, -1);
        Date startDate = calendar.getTime();

        calendar.add(Calendar.YEAR, 1);
        Date endDate = calendar.getTime();

        // Initialize a new KeyPair generator
        ContentSigner rootCertContentSigner;
        KeyPair rootKeyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
            keyPairGenerator.initialize(2048);
            rootKeyPair = keyPairGenerator.generateKeyPair();
            certificateManager.setRootCertKeyPair(rootKeyPair);
            rootCertContentSigner = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(rootKeyPair.getPrivate());
        } catch (NoSuchAlgorithmException | NoSuchProviderException | OperatorCreationException  e) {
            throw new RuntimeException(e.getMessage());
        }


        // First step is to create a root certificate
        // First Generate a KeyPair,
        // then a random serial number
        // then generate a certificate using the KeyPair

        BigInteger rootSerialNum = new BigInteger(Long.toString(new SecureRandom().nextLong()));
        certificateManager.setRootCertIssuerName( new X500Name(certificateManager.getCERTIFICATE_ISSUER()));
        X500Name rootCertSubject = certificateManager.getRootCertIssuerName();

        X509v3CertificateBuilder rootCertBuilder = new JcaX509v3CertificateBuilder(certificateManager.getRootCertIssuerName(), rootSerialNum, startDate, endDate, rootCertSubject, rootKeyPair.getPublic());


        // Add Extensions
        // A BasicConstraint to mark root certificate as CA certificate
        try {
            JcaX509ExtensionUtils rootCertExtUtils = new JcaX509ExtensionUtils();
            rootCertBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            rootCertBuilder.addExtension(Extension.subjectKeyIdentifier, false, rootCertExtUtils.createSubjectKeyIdentifier(rootKeyPair.getPublic()));
            // Create a cert holder and export to X509Certificate
            X509CertificateHolder rootCertHolder = rootCertBuilder.build(rootCertContentSigner);
            X509Certificate rootCert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(rootCertHolder);
            certificateManager.setRootCertificate(rootCert);
        } catch (NoSuchAlgorithmException | CertIOException | CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    public String makeCertificate(CertificateInfo certificateInfo) throws NoSuchAlgorithmException, CertificateException, OperatorCreationException {
        certificateManager = CertificateUtil.makeCertificateManager(certificateInfo, certificateManager);
        CertificateUtil.getSelfSignCertificate(certificateManager);
        log.info("certificate: " + certificateManager.getClientCertificate().toString());
        return certificateManager.getClientCertificate().toString();
    }

    public String addDistributionList(String crlUri) {
        if(!isCertificateManagerValid()){
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
            CertificateUtil.getSelfSignCertificate(certificateManager);
        } catch (Exception e) {
            return "CRL Distribution Point already exist: "+e.getMessage();
        }
        return crlUri+" is added to the distributionList of x509Certificate";
    }

    public String removeDistributionList(String crlUri) {
        if(!isCertificateManagerValid()){
            return "certificate is not created yet. Pls make a certificate first";
        }
       // certificateManager.getCertBuilder().removeExtension(Extension.cRLDistributionPoints);
        CertificateUtil.getSelfSignCertificate(certificateManager);

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

    public String isCertificateValid(){
        if(!isCertificateManagerValid()){
            return "certificate is not created yet. Pls make a certificate first";
        }
        return CertificateUtil.isCertificateValid(certificateManager.getClientCertificate());
    }
    public boolean isCertificateManagerValid(){
        if(certificateManager.getClientCertificate() == null){
            return false;
        }else{
            return true;
        }
    }
    public String getCertificateFile(){
        if(!isCertificateManagerValid()){
            return "certificate is not created yet. Pls make a certificate first";
        }
        StringWriter sw = new StringWriter();
        try (JcaPEMWriter jpw = new JcaPEMWriter(sw)) {
            jpw.writeObject(certificateManager.getClientCertificate());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return sw.toString();
    }
    static public void loadRootCertAndPrivateKey(){
        try {
//            ClassPathResource resource = new ClassPathResource(ROOT_JAVA_KEY_STORE);
            FileInputStream is = new FileInputStream(getRootKeyPath(ROOT_JAVA_KEY_STORE));
            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            keystore.load(is, ROOT_CERTIFICATE_PASSWORD.toCharArray());
            PrivateKey rootPrivateKey = (PrivateKey) keystore.getKey(ROOT_CERTIFICATE_ALIAS, ROOT_CERTIFICATE_PASSWORD.toCharArray());
            X509Certificate rootCertificate = (X509Certificate) keystore.getCertificate(ROOT_CERTIFICATE_ALIAS);
            System.out.println("stop here");
        } catch (IOException | UnrecoverableKeyException | CertificateException | KeyStoreException |
                 NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    static public void loadRootCertAndPrivateKey2(){
        try {
            FileOutputStream os = new FileOutputStream("rootCA.jks");
            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            keystore.load(null, "password".toCharArray());

            FileInputStream certInputStream = new FileInputStream("rootCA.crt");
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) certFactory.generateCertificate(certInputStream);

            keystore.setCertificateEntry("root", cert);
            keystore.store(os, "password".toCharArray());
            PrivateKey rootPrivateKey = (PrivateKey) keystore.getKey(ROOT_CERTIFICATE_ALIAS, ROOT_CERTIFICATE_PASSWORD.toCharArray());
            os.close();            System.out.println("stop here");
        } catch (IOException | CertificateException | KeyStoreException | NoSuchAlgorithmException |
                 UnrecoverableKeyException e) {
            throw new RuntimeException(e);
        }
    }

    public static String getRootKeyPath(String resourceName){
        String rootKeyDir = "src"+File.separator+"main"+File.separator+"resources"+File.separator+"root-key";
        try {
            String localPath = new File(".").getCanonicalPath();
            return localPath+File.separator+rootKeyDir+File.separator+resourceName;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }


}