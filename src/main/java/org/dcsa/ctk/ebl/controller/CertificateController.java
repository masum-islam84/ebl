package org.dcsa.ctk.ebl.controller;

import org.dcsa.ctk.ebl.domain.CertificateInfo;
import org.dcsa.ctk.ebl.service.X509CertificateManager;
import org.dcsa.ctk.ebl.service.caverify.RevocationVerifier;
import org.springframework.web.bind.annotation.*;

import static org.dcsa.ctk.ebl.controller.CertificateController.ROOT_URL;


@RestController
@RequestMapping(value = ROOT_URL)
public class CertificateController {
    public static final String ROOT_URL = "/ebl";
    private final String MAKE_CERTIFICATE = "/makeCertificate";
    private final String IS_VALID = "/isValid";

    private final String VERIFY_DISTRIBUTION_LIST = "/verifyDistributionList";
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
    public String addDistributionList( @RequestBody String crlUri){
        return x509CertificateManager.addDistributionList(crlUri);
    }

    @GetMapping(path = VERIFY_DISTRIBUTION_LIST)
    public String isDistributionValid(){
        if(!x509CertificateManager.isCertificateManagerValid()){
          //  return
        }
        //revocationVerifier.
        return x509CertificateManager.isCertificateValid();
    }





}
