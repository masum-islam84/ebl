package org.dcsa.ctk.ebl.domain;

import lombok.Data;

@Data
public class CertificateInfo {
    private String subjectDN;
    private long days;
    private String crlUri;
}
