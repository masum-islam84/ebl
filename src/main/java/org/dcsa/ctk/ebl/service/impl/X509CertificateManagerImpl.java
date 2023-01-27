package org.dcsa.ctk.ebl.service.impl;

import lombok.extern.java.Log;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.dcsa.ctk.ebl.domain.CertificateInfo;
import org.dcsa.ctk.ebl.domain.CertificateManager;
import org.dcsa.ctk.ebl.service.X509CertificateManager;
import org.dcsa.ctk.ebl.util.CertificateUtil;
import org.springframework.stereotype.Service;

@Log
@Service
public class X509CertificateManagerImpl implements X509CertificateManager {
    private CertificateManager certificateManager;

    public X509CertificateManagerImpl(){
        certificateManager = new CertificateManager();
    }
    public String makeCertificate(CertificateInfo certificateInfo) {
        certificateManager = CertificateUtil.makeCertificateManager(certificateInfo.getSubjectDN(), CertificateUtil.convertDate(certificateInfo.getDays()), certificateManager);
        CertificateUtil.getSelfSignCertificate(certificateManager);
        log.info("certificate: " + certificateManager.getX509Certificate().toString());
        return certificateManager.getX509Certificate().toString();
    }

    public String addDistributionList(String crlUri) {
        if(!isCertificateManagerValid()){
            return "certificate is not created yet. Pls make a certificate first";
        }
        GeneralName generalName = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(crlUri));
        GeneralNames generalNames = new GeneralNames(generalName);
        DistributionPointName distPointName = new DistributionPointName(generalNames);
        DistributionPoint distPoint = new DistributionPoint(distPointName, null, generalNames);
        DistributionPoint[] crlDistPoints = new DistributionPoint[] { distPoint };
        CRLDistPoint crlDistPoint = new CRLDistPoint(crlDistPoints);
        try {
            certificateManager.getCertBuilder().addExtension(Extension.cRLDistributionPoints, true, crlDistPoint);
            CertificateUtil.getSelfSignCertificate(certificateManager);
        } catch (CertIOException e) {
            throw new RuntimeException(e.getMessage());
        }
        return crlUri+" is added to the distributionList of x509Certificate";
    }

    public String removeDistributionList(String crlUri) {
        if(!isCertificateManagerValid()){
            return "certificate is not created yet. Pls make a certificate first";
        }
        certificateManager.getCertBuilder().removeExtension(new ASN1ObjectIdentifier("2.5.29.19"));
        CertificateUtil.getSelfSignCertificate(certificateManager);

/*        GeneralName generalName = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(crlUri));
        GeneralNames generalNames = new GeneralNames(generalName);
        DistributionPointName distPointName = new DistributionPointName(generalNames);
        DistributionPoint distPoint = new DistributionPoint(distPointName, null, generalNames);
        DistributionPoint[] crlDistPoints = new DistributionPoint[] { distPoint };
        CRLDistPoint crlDistPoint = new CRLDistPoint(crlDistPoints);
        try {
            certificateManager.getCertBuilder().addExtension(Extension.cRLDistributionPoints, true, crlDistPoint);
            CertificateUtil.getSelfSignCertificate(certificateManager);
        } catch (CertIOException e) {
            throw new RuntimeException(e.getMessage());
        }*/
        return crlUri+" is removed from distributionList of x509Certificate";
    }

    public String getDistributionList(){
        return  "";
    }

    public String isCertificateValid(){
        if(!isCertificateManagerValid()){
            return "certificate is not created yet. Pls make a certificate first";
        }
        return CertificateUtil.isCertificateValid(certificateManager.getX509Certificate());
    }
    public boolean isCertificateManagerValid(){
        if(certificateManager.getX509Certificate() == null && certificateManager.getCertBuilder() == null && certificateManager.getKeyPair() == null){
            return false;
        }else{
            return true;
        }
    }

}