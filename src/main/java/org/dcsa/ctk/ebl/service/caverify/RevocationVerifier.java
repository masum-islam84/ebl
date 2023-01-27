package org.dcsa.ctk.ebl.service.caverify;


import org.dcsa.ctk.ebl.service.caverify.exception.CertificateVerificationException;

import java.security.cert.X509Certificate;

/**
 * All the revocation verifiers should implement this interface.
 */
public interface RevocationVerifier {

    public RevocationStatus checkRevocationStatus(X509Certificate peerCert, X509Certificate issuerCert);
}
