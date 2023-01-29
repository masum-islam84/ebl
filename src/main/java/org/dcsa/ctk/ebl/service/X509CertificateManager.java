package org.dcsa.ctk.ebl.service;

import org.dcsa.ctk.ebl.domain.CertificateInfo;
import org.dcsa.ctk.ebl.domain.CertificateManager;
import org.dcsa.ctk.ebl.service.caverify.exception.CertificateVerificationException;

import java.security.cert.X509Certificate;
import java.util.List;

public interface X509CertificateManager {
    String makeCertificate(CertificateInfo certificateInfo);
    String addDistributionList(String crlUri);
    public String isCertificateValid();
    boolean isCertificateManagerValid();
   CertificateManager getCertificateManager();
   String removeDistributionList(String crlUri);

}
