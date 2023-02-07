package org.dcsa.ctk.ebl.service;

import org.bouncycastle.operator.OperatorCreationException;
import org.dcsa.ctk.ebl.domain.CertificateInfo;
import org.dcsa.ctk.ebl.domain.enums.CertificateTrust;
import org.dcsa.ctk.ebl.dto.CertificateDto;
import org.springframework.http.ResponseEntity;

import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public interface X509CertificateManager {
    ResponseEntity<byte[]> makeClientCertificate(CertificateInfo certificateInfo, CertificateTrust certificateTrust) throws Exception;

    ResponseEntity<byte[]> getCertificateFile(String filename);

    X509Certificate getClientCertificate();

    String addDistributionList(String crlUri);

    boolean isRootCertificateInitialized();

    String isClientCertificateValid();

    // CertificateManager getCertificateManager();
    boolean isClientCertificateInitialized();

    String removeDistributionList(String crlUri);

    //  String getCertificateFile();
    void setClientCertificate(X509Certificate certificate);

    X509Certificate signCertificate(X509Certificate certificate) throws Exception;

    String isClientCertificateSinged();

    void setClientCommonName(String commonName);

    X509Certificate removeSignature(X509Certificate signedCertificate) throws NoSuchAlgorithmException, OperatorCreationException, CertificateException;

    String getCertificateStr();
    PublicKey getPublicKey();
    void setPublicKey(PublicKey publicKey);
}
