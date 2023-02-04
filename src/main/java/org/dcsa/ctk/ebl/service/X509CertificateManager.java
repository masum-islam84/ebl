package org.dcsa.ctk.ebl.service;

import org.bouncycastle.operator.OperatorCreationException;
import org.dcsa.ctk.ebl.domain.CertificateInfo;
import org.dcsa.ctk.ebl.domain.CertificateManager;

import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

public interface X509CertificateManager {
    String makeCertificate(CertificateInfo certificateInfo) throws NoSuchAlgorithmException, CertificateException, OperatorCreationException;
    String addDistributionList(String crlUri);
    public String isCertificateValid();
    boolean isCertificateManagerValid();
   CertificateManager getCertificateManager();
   String removeDistributionList(String crlUri);
   String getCertificateFile();

}
