package org.dcsa.ctk.ebl.domain;

import lombok.Data;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;

import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

@Data
public class CertificateManager {
    private final String CERTIFICATE_ISSUER = "CN=Root CA, O=My Organization, L=My City, ST=My State, C=My Country, emailAddress=rootca@test.com";
    private X509v3CertificateBuilder certificateBuilder;
    private KeyPair rootCertKeyPair;
    private KeyStore rootKeyStore;
    private X500Name rootCertIssuerName;
    private X509Certificate clientCertificate;
    private CertificateInfo clientCertificateInfo;
    private KeyStore keyStore;
    private X509Certificate rootCertificate;
}
