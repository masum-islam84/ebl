package org.dcsa.ctk.ebl.domain;

import lombok.Data;

import java.security.PublicKey;
import java.util.Date;

@Data
public class CertificateInfo {

    private String commonName;
    private String organizationalUnit;
    private String organization;
    private String locality;
    private String state;
    private String country;
    private Date startDate;
    private Date endDate;
    private String publicKey;
 //   private PublicKey publicKey;

    private String subjectDN;
    private long days;
    private String crlUri;
}

