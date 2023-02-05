package org.dcsa.ctk.ebl.service;

import org.bouncycastle.operator.OperatorCreationException;
import org.dcsa.ctk.ebl.domain.CertificateInfo;
import org.dcsa.ctk.ebl.dto.CertificateDto;

import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public interface X509CertificateManager {
    CertificateDto makeClientCertificateUnsigned(CertificateInfo certificateInfo) throws Exception;
    CertificateDto makeClientCertificateUnsigned(X509Certificate certificate) throws Exception;
    X509Certificate getClientCertificate();
    String addDistributionList(String crlUri);
    boolean isRootCertificateInitialized();
    String isClientCertificateValid();
  // CertificateManager getCertificateManager();
  boolean isClientCertificateInitialized();
   String removeDistributionList(String crlUri);
   String getCertificateFile();
   void setClientCertificate(X509Certificate certificate);
   X509Certificate signCertificate(X509Certificate certificate) throws Exception;
   String isClientCertificateSinged();
   void setClientCommonName(String commonName);
   X509Certificate removeSignature(X509Certificate signedCertificate) throws NoSuchAlgorithmException, OperatorCreationException, CertificateException;
}
