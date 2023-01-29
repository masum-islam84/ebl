package org.dcsa.ctk.ebl.controller;

import org.dcsa.ctk.ebl.domain.CertificateInfo;
import org.dcsa.ctk.ebl.service.X509CertificateManager;
import org.dcsa.ctk.ebl.service.caverify.RevocationVerifier;
import org.dcsa.ctk.ebl.service.caverify.exception.CertificateVerificationException;
import org.springframework.web.bind.annotation.*;

import java.util.List;

import static org.dcsa.ctk.ebl.controller.CertificateController.ROOT_URL;


@RestController
@RequestMapping(value = ROOT_URL)
public class CertificateController {
    public static final String ROOT_URL = "/ebl";
    private final String MAKE_CERTIFICATE = "/makeCertificate";
    private final String IS_VALID = "/isValid";
    private final String VERIFY_DISTRIBUTION_LIST = "/verifyDistributionList";

    private final String GET_ALL_DISTRIBUTION_LIST = "/allDistributionList";

    private final String  REMOVE_DISTRIBUTION_LIST = "/removeDistributionList";
    private final String ADD_DISTRIBUTION_LIST = "/addDistributionList";

    private final X509CertificateManager x509CertificateManager;
    private final RevocationVerifier revocationVerifier;

    public CertificateController(X509CertificateManager x509CertificateManager, RevocationVerifier revocationVerifier) {
        this.x509CertificateManager = x509CertificateManager;
        this.revocationVerifier = revocationVerifier;
    }

    @PostMapping(path = MAKE_CERTIFICATE)
    public String makeCertificate(@RequestBody CertificateInfo certificateInfo){
        return x509CertificateManager.makeCertificate(certificateInfo);
    }

    @GetMapping(path = IS_VALID)
    public String isCertificateValid(){
        return x509CertificateManager.isCertificateValid();
    }

    @PostMapping(path = ADD_DISTRIBUTION_LIST)
    public String addDistributionList( @RequestBody CertificateInfo certificateInfo){
        return x509CertificateManager.addDistributionList(certificateInfo.getCrlUri());
    }

    @DeleteMapping(path = REMOVE_DISTRIBUTION_LIST)
    public String removeDistributionValid(@RequestBody CertificateInfo certificateInfo){
        if(!x509CertificateManager.isCertificateManagerValid()){
            return "certificate is not created yet. Pls make a certificate first";
        }
        return x509CertificateManager.removeDistributionList(certificateInfo.getCrlUri());
    }

    @GetMapping(path = VERIFY_DISTRIBUTION_LIST)
    public String isDistributionValid(){
        if(!x509CertificateManager.isCertificateManagerValid()){
            return "certificate is not created yet. Pls make a certificate first";
        }
      return  revocationVerifier.checkRevocationStatus(x509CertificateManager.getCertificateManager().getX509Certificate(), null).getMessage();
    }

    @GetMapping(path = GET_ALL_DISTRIBUTION_LIST)
    public List<String> allDistributionValid() throws CertificateVerificationException {
        if(!x509CertificateManager.isCertificateManagerValid()){
            return List.of("certificate is not created yet. Pls make a certificate first");
        }
        return  revocationVerifier.getCrlDistributionPoints(x509CertificateManager.getCertificateManager().getX509Certificate());
    }







}
