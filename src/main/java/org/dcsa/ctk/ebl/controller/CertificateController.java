package org.dcsa.ctk.ebl.controller;

import org.dcsa.ctk.ebl.config.AppProperty;
import org.dcsa.ctk.ebl.domain.CertificateInfo;
import org.dcsa.ctk.ebl.dto.CertificateDto;
import org.dcsa.ctk.ebl.service.UploadService;
import org.dcsa.ctk.ebl.service.X509CertificateManager;
import org.dcsa.ctk.ebl.service.caverify.RevocationVerifier;
import org.dcsa.ctk.ebl.service.exception.CertificateVerificationException;
import org.dcsa.ctk.ebl.util.CertificateUtil;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Objects;

import static org.dcsa.ctk.ebl.controller.CertificateController.ROOT_EBL_URL;

@RestController
@RequestMapping(value = ROOT_EBL_URL)
public class CertificateController {
    public static final String ROOT_EBL_URL = "/ebl";

    private final String MAKE_CLIENT_CERTIFICATE = "/makeClientCertificate";
    private final String IS_VALID = "/isValid";
    private final String VERIFY_DISTRIBUTION_LIST = "/verifyDistributionList";

    private final String GET_ALL_DISTRIBUTION_LIST = "/allDistributionList";

    private final String  REMOVE_DISTRIBUTION_LIST = "/removeDistributionList";
    private final String ADD_DISTRIBUTION_LIST = "/addDistributionList";

    private final String GET_CERTIFICATE = "/getCertificate";

    private final String USE_CERTIFICATE = "/useCertificate";

    private final String SIGN_CERTIFICATE = "/signCertificate";

    private final String SIGN_CERTIFICATE_FILE = "/signCertificateFile";

    private final String REVOKE_SIGNATURE = "/revokeSignature";

    private final String IS_CLIENT_CERTIFICATE_SIGNED = "/isClientCertificateSigned";

    private final X509CertificateManager x509CertificateManager;
    private final RevocationVerifier revocationVerifier;
    private final AppProperty appProperty;

    private final UploadService uploadService;

    public CertificateController(X509CertificateManager x509CertificateManager, RevocationVerifier revocationVerifier, AppProperty appProperty, UploadService uploadService) {
        this.x509CertificateManager = x509CertificateManager;
        this.revocationVerifier = revocationVerifier;
        this.appProperty = appProperty;
        this.uploadService = uploadService;
        appProperty.init();
    }

    @PostMapping(path = MAKE_CLIENT_CERTIFICATE)
    public CertificateDto makeCertificate(@RequestBody CertificateInfo certificateInfo) throws Exception {
        return x509CertificateManager.makeClientCertificateUnsigned(certificateInfo);
    }


    @GetMapping(path = IS_VALID)
    public String isCertificateValid(){
        return x509CertificateManager.isClientCertificateValid();
    }

    @PostMapping(path = ADD_DISTRIBUTION_LIST)
    public String addDistributionList( @RequestBody CertificateInfo certificateInfo){
        return x509CertificateManager.addDistributionList(certificateInfo.getCrlUri());
    }

    @DeleteMapping(path = REMOVE_DISTRIBUTION_LIST)
    public String removeDistributionValid(@RequestBody CertificateInfo certificateInfo){
        if(!x509CertificateManager.isClientCertificateInitialized()){
            return "certificate is not created yet. Pls make a certificate first";
        }
        return x509CertificateManager.removeDistributionList(certificateInfo.getCrlUri());
    }

    @GetMapping(path = VERIFY_DISTRIBUTION_LIST)
    public String isDistributionValid(){
        if(!x509CertificateManager.isClientCertificateInitialized()){
            return "certificate is not created yet. Pls make a certificate first";
        }
      return  revocationVerifier.checkRevocationStatus(x509CertificateManager.getClientCertificate(), null).getMessage();
    }
    @GetMapping(path = GET_ALL_DISTRIBUTION_LIST)
    public List<String> allDistributionValid() throws CertificateVerificationException {
        if(!x509CertificateManager.isClientCertificateInitialized()){
            return List.of("certificate is not created yet. Pls make a certificate first");
        }
        return  revocationVerifier.getCrlDistributionPoints(x509CertificateManager.getClientCertificate());
    }
    @GetMapping(path = GET_CERTIFICATE)
    public ResponseEntity<byte[]> getCertificate(@RequestParam(defaultValue = "dcsa_certificate.cert") String fileName){
        return CertificateUtil.getCertificate(fileName, x509CertificateManager);
    }
    @PostMapping(path = USE_CERTIFICATE)
    public String useCertificate(@RequestParam("file") MultipartFile file){
        uploadService.store(file, AppProperty.uploadPath);
        return "uploaded "+file.getOriginalFilename();
    }

    @GetMapping(path = SIGN_CERTIFICATE)
    public ResponseEntity<byte[]> singCertificate(@RequestParam(defaultValue = "dcsa_certificate.cert") String fileName) throws Exception {
        if(!x509CertificateManager.isClientCertificateInitialized()){
            HttpHeaders headers = new HttpHeaders();
            headers.add("Content-Type", "application/json; charset=utf-8");
            return new ResponseEntity<>("certificate is not created yet. Pls make a certificate first".getBytes(), headers, HttpStatus.NOT_FOUND);
        }
        x509CertificateManager.setClientCertificate(x509CertificateManager.signCertificate(x509CertificateManager.getClientCertificate()));
        fileName = CertificateUtil.renameFilename(Objects.requireNonNull(fileName));
        return CertificateUtil.getCertificate(fileName, x509CertificateManager);
    }
    @PostMapping(path = SIGN_CERTIFICATE_FILE)
    public ResponseEntity<byte[]> signCertificateFile(@RequestParam("file") MultipartFile file) throws Exception {
        X509Certificate  certificate = CertificateUtil.makeCertificateFromMultipartFile(file);
        x509CertificateManager.setClientCertificate(x509CertificateManager.signCertificate(certificate));
        String fileName = CertificateUtil.renameFilename(Objects.requireNonNull(file.getOriginalFilename()));
        return CertificateUtil.getCertificate(fileName, x509CertificateManager);
    }
    @GetMapping(path = IS_CLIENT_CERTIFICATE_SIGNED)
    public String isClientCertificateSinged(){
        return x509CertificateManager.isClientCertificateSinged();
    }
    @PutMapping(path = REVOKE_SIGNATURE)
    public CertificateDto revokeSignature(@RequestParam("file") MultipartFile file) throws Exception {
        X509Certificate  certificate = CertificateUtil.makeCertificateFromMultipartFile(file);
        X509Certificate x509Certificate =  x509CertificateManager.removeSignature(certificate);
        return new CertificateDto(x509Certificate);
    }
}
