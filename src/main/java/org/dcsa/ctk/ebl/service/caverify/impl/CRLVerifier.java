package org.dcsa.ctk.ebl.service.caverify.impl;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.*;
import org.dcsa.ctk.ebl.service.caverify.RevocationStatus;
import org.dcsa.ctk.ebl.service.caverify.RevocationVerifier;
import org.dcsa.ctk.ebl.service.exception.CertificateVerificationException;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.List;


/**
 * This is used to verify a certificate is revoked or not by using the Certificate Revocation List published
 * by the CA.
 */

@Service
public class CRLVerifier implements RevocationVerifier {
    private CRLCache cache;

    private final static String NO_CLR ="Certificate doesn't have CRL Distribution points";

    private static final Log log = LogFactory.getLog(CRLVerifier.class);
    public CRLVerifier(CRLCache cache) {
        this.cache = cache;
    }

    /**
     * Checks revocation status (Good, Revoked) of the peer certificate. IssuerCertificate can be used
     * to check if the CRL URL has the Issuers Domain name. But this is not implemented at the moment.
     *
     * @param peerCert   peer certificate
     * @param issuerCert issuer certificate of the peer. not used currently.
     * @return revocation status of the peer certificate.
     */

    public RevocationStatus checkRevocationStatus(X509Certificate peerCert, X509Certificate issuerCert) {

        List<String> list = getCrlDistributionPoints(peerCert);
        if(list.contains(NO_CLR)){
            return RevocationStatus.NO_DISTRIBUTION;
        }
        RevocationStatus status = RevocationStatus.UNKNOWN;
        for (String crlUrl : list) {
            log.info("Trying to get CRL for URL: " + crlUrl);
            if (cache != null) {
                X509CRL x509CRL;
                try {
                    x509CRL = downloadCRLFromWeb(crlUrl);
                } catch (IOException | CertificateVerificationException e) {
                    throw new RuntimeException(e);
                }
                if (x509CRL != null) {
                    //If cant be casted, we have used the wrong cache.
                    status = getRevocationStatus(x509CRL, peerCert);
                    return status;
                }
            }

            //todo: Do we need to check if URL has the same domain name as issuerCert?
            //todo: What if this certificate is Unknown?????
/*            try {
                /// todo  updte here for my code
                X509CRL x509CRL = downloadCRLFromWeb(crlUrl);
                if (x509CRL != null) {
                    if (cache != null)
                        cache.setCacheValue(crlUrl, x509CRL);
                    return getRevocationStatus(x509CRL, peerCert);
                }
            } catch (Exception e) {
                log.info("Either url is bad or cant build X509CRL. So check with the next url in the list.", e);
            }*/
        }
        return status;
    }

    private RevocationStatus getRevocationStatus(X509CRL x509CRL, X509Certificate peerCert) {
        if (x509CRL.isRevoked(peerCert)) {
            return RevocationStatus.REVOKED;
        } else {
            return RevocationStatus.GOOD;
        }
    }

    /**
     * Downloads CRL from the crlUrl. Does not support HTTPS
     */
    protected X509CRL downloadCRLFromWeb(String crlURL)
            throws IOException, CertificateVerificationException {
        InputStream crlStream = null;
        try {
            URL url = new URL(crlURL);
            crlStream = url.openStream();
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509CRL) cf.generateCRL(crlStream);
        } catch (MalformedURLException e) {
            throw new CertificateVerificationException("CRL Url is malformed", e);
        } catch (IOException e) {
            throw new CertificateVerificationException("Cant reach URI: " + crlURL + " - only support HTTP", e);
        } catch (CertificateException e) {
            throw new CertificateVerificationException(e);
        } catch (CRLException e) {
            throw new CertificateVerificationException("Cannot generate X509CRL from the stream data", e);
        } finally {
            if (crlStream != null)
                crlStream.close();
        }
    }

    /**
     * Extracts all CRL distribution point URLs from the "CRL Distribution Point"
     * extension in a X.509 certificate. If CRL distribution point extension is
     * unavailable, returns an empty list.
     */
    public List<String> getCrlDistributionPoints(X509Certificate cert){

        //Gets the DER-encoded OCTET string for the extension value for CRLDistributionPoints
        byte[] crlDPExtensionValue = cert.getExtensionValue(Extension.cRLDistributionPoints.getId());
        if (crlDPExtensionValue == null){
           return List.of(NO_CLR);
        }
        //crlDPExtensionValue is encoded in ASN.1 format.
        ASN1InputStream asn1In = new ASN1InputStream(crlDPExtensionValue);
        //DER (Distinguished Encoding Rules) is one of ASN.1 encoding rules defined in ITU-T X.690, 2002, specification.
        //ASN.1 encoding rules can be used to encode any data object into a binary file. Read the object in octets.
        CRLDistPoint distPoint = null;
        try {
            DEROctetString crlDEROctetString = (DEROctetString) asn1In.readObject();
            //Get Input stream in octets
            ASN1InputStream asn1InOctets = new ASN1InputStream(crlDEROctetString.getOctets());
            ASN1Primitive crlDERObject = asn1InOctets.readObject();
            distPoint = CRLDistPoint.getInstance(crlDERObject);
        } catch (IOException e) {
            return List.of(NO_CLR);
        }

        List<String> crlUrls = new ArrayList<>();
        //Loop through ASN1Encodable DistributionPoints
        for (DistributionPoint dp : distPoint.getDistributionPoints()) {
            //get ASN1Encodable DistributionPointName
            DistributionPointName dpn = dp.getDistributionPoint();
            if (dpn != null && dpn.getType() == DistributionPointName.FULL_NAME) {
                //Create ASN1Encodable General Names
                GeneralName[] genNames = GeneralNames.getInstance(dpn.getName()).getNames();
                // Look for a URI
                //todo: May be able to check for OCSP url specifically.
                for (GeneralName genName : genNames) {
                    if (genName.getTagNo() == GeneralName.uniformResourceIdentifier) {
                        //DERIA5String contains an ascii string.
                        //A IA5String is a restricted character string type in the ASN.1 notation
                        String url = DERIA5String.getInstance(genName.getName()).getString().trim();
                        crlUrls.add(url);
                    }
                }
            }
        }

        if (crlUrls.isEmpty()) {
           return List.of(NO_CLR);
        }
        return crlUrls;
    }
}
