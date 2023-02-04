package org.dcsa.ctk.ebl.dto;

import java.security.cert.X509Certificate;

public class CertificateDto {
    private String certificate;

    public CertificateDto(X509Certificate x509Certificate) {
        this.certificate = x509Certificate.toString();
    }

    public String getCertificate() {
        return certificate;
    }

    public void setCertificate(String certificate) {
        this.certificate = certificate;
    }
}

