package org.dcsa.ctk.ebl.service;

import org.dcsa.ctk.ebl.domain.CertificateInfo;

public interface X509CertificateManager {
    String makeCertificate(CertificateInfo certificateInfo);
    String addDistributionList(String crlUri);
    public String isCertificateValid();
    boolean isCertificateManagerValid();

}
