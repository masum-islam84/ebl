package org.dcsa.ctk.ebl.util;

import lombok.extern.java.Log;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.dcsa.ctk.ebl.domain.CertificateInfo;
import org.dcsa.ctk.ebl.domain.CertificateManager;
import org.dcsa.ctk.ebl.service.X509CertificateManager;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.multipart.MultipartFile;

import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.*;
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
    static public X509Certificate makeCertificateFromMultipartFile(MultipartFile file) throws IOException, CertificateException {
        byte[] certificateData = file.getBytes();
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        InputStream inputStream = new ByteArrayInputStream(certificateData);
        X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(inputStream);
        return certificate;
    }

    static public CertificateInfo getCertificateInfoFromX509Certificate(X509Certificate certificate){
        CertificateInfo certificateInfo = new CertificateInfo();

        X500Principal subjectPrincipal = certificate.getSubjectX500Principal();
        String subjectDN = subjectPrincipal.getName();

        int cnStartIndex = subjectDN.indexOf("CN=") + 3;
        int cnEndIndex = subjectDN.indexOf(',', cnStartIndex);
        if (cnEndIndex == -1) {
            cnEndIndex = subjectDN.length();
        }
        certificateInfo.setCommonName(subjectDN.substring(cnStartIndex, cnEndIndex));

        int ouStartIndex = subjectDN.indexOf("OU=") + 3;
        int ouEndIndex = subjectDN.indexOf(',', ouStartIndex);
        if (ouEndIndex == -1) {
            ouEndIndex = subjectDN.length();
        }
        certificateInfo.setOrganizationalUnit(subjectDN.substring(ouStartIndex, ouEndIndex));

        int oStartIndex = subjectDN.indexOf("O=") + 2;
        int oEndIndex = subjectDN.indexOf(',', oStartIndex);
        if (oEndIndex == -1) {
            oEndIndex = subjectDN.length();
        }
        certificateInfo.setOrganization(subjectDN.substring(oStartIndex, oEndIndex));

        int lStartIndex = subjectDN.indexOf("L=") + 2;
        int lEndIndex = subjectDN.indexOf(',', lStartIndex);
        if (lEndIndex == -1) {
            lEndIndex = subjectDN.length();
        }
        certificateInfo.setLocality(subjectDN.substring(lStartIndex, lEndIndex));

        int stStartIndex = subjectDN.indexOf("ST=") + 3;
        int stEndIndex = subjectDN.indexOf(',', stStartIndex);
        if (stEndIndex == -1) {
            stEndIndex = subjectDN.length();
        }
        certificateInfo.setState(subjectDN.substring(stStartIndex, stEndIndex));

        int cStartIndex = subjectDN.indexOf("C=") + 2;
        int cEndIndex = subjectDN.indexOf(',', cStartIndex);
        if (cEndIndex == -1) {
            cEndIndex = subjectDN.length();
        }
        certificateInfo.setCountry(subjectDN.substring(cStartIndex, cEndIndex));

        certificateInfo.setStartDate(certificate.getNotBefore());
        certificateInfo.setEndDate(certificate.getNotAfter());
        return certificateInfo;
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

    static public ResponseEntity<byte[]> getCertificateFile(String fileName, X509CertificateManager x509CertificateManager){
        String headerValues = "attachment;filename="+fileName;
        if(!x509CertificateManager.isClientCertificateInitialized()){
            HttpHeaders headers = new HttpHeaders();
            headers.add("Content-Type", "application/json; charset=utf-8");
            return new ResponseEntity<>("certificate is not created yet. Pls make a certificate first".getBytes(), headers, HttpStatus.NOT_FOUND);
        }
        byte[] bytes =  x509CertificateManager.getCertificateStr().getBytes();
        return ResponseEntity
                .status(HttpStatus.CREATED)
                .header(HttpHeaders.CONTENT_DISPOSITION, headerValues)
                .contentType(MediaType.APPLICATION_JSON)
                .contentLength(bytes.length)
                .body(bytes);
    }
    static public String renameFilename(String filename){
        String[] tokens = filename.split("\\.");
        if(tokens.length > 1){
            String extension = tokens[1].replace(tokens[1], "-signed."+tokens[1]);
            filename = tokens[0]+extension;
        }
        return filename;
    }

    static void writeCertToFileBase64Encoded(Certificate certificate, String fileName) throws Exception {
        StringWriter sw = new StringWriter();
        try (JcaPEMWriter jpw = new JcaPEMWriter(sw)) {
            jpw.writeObject(certificate);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        String pem = sw.toString();
        Path path = Paths.get(fileName);
        byte[] strToBytes = pem.getBytes();
        Files.write(path, strToBytes);
    }

    public static Date convertDate(long days){
        LocalDateTime localDateTime = LocalDateTime.now().plusDays(days);
        Date date =  java.sql.Timestamp.valueOf(localDateTime);
        return date;
    }
}
