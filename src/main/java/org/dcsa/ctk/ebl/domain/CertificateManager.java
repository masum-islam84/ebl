package org.dcsa.ctk.ebl.domain;

import lombok.Data;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;

import java.security.KeyPair;
import java.security.cert.X509Certificate;

@Data
public class CertificateManager {
    private X509Certificate x509Certificate;
    private JcaX509v3CertificateBuilder certBuilder;
    private KeyPair keyPair;
}
