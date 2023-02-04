package org.dcsa.ctk.ebl.domain;

import lombok.Data;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

@Data
public class CertificateManager {
    private final String CERTIFICATE_ISSUER = "CN=Root CA, O=My Organization, L=My City, ST=My State, C=My Country, emailAddress=rootca@test.com";
  //  private X509Certificate x509Certificate;
  //  private JcaX509v3CertificateBuilder certBuilder;
    private X509v3CertificateBuilder certificateBuilder;
    private KeyPair rootCertKeyPair;
    //private PrivateKey rootPrivateKey;
    private X500Name rootCertIssuerName;
    private X509Certificate rootCertificate;
    private X509Certificate clientCertificate;
}
