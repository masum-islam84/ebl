package org.dcsa.ctk.ebl.controller;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.dcsa.ctk.ebl.config.AppProperty;
import org.dcsa.ctk.ebl.domain.CertificateInfo;
import org.dcsa.ctk.ebl.dto.CertificateDto;
import org.dcsa.ctk.ebl.service.UploadService;
import org.dcsa.ctk.ebl.service.X509CertificateManager;
import org.dcsa.ctk.ebl.service.caverify.RevocationVerifier;
import org.dcsa.ctk.ebl.service.exception.CertificateVerificationException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
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

    private final String GET_CERTIFICATE = "/getCertificate";

    private final String USE_CERTIFICATE = "/useCertificate";

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

    @PostMapping(path = MAKE_CERTIFICATE)
    public CertificateDto makeCertificate(@RequestBody CertificateInfo certificateInfo) throws Exception {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.CN, certificateInfo.getCommonName());
        builder.addRDN(BCStyle.OU, certificateInfo.getOrganizationalUnit());
        builder.addRDN(BCStyle.O, certificateInfo.getOrganization());
        builder.addRDN(BCStyle.L, certificateInfo.getLocality());
        builder.addRDN(BCStyle.ST, certificateInfo.getState());
        builder.addRDN(BCStyle.C, certificateInfo.getCountry());

        X500Name subject = builder.build();
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();

        X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
                subject,
                BigInteger.valueOf(System.currentTimeMillis()),
                new java.util.Date(certificateInfo.getStartDate().getTime()),
                new java.util.Date(certificateInfo.getEndDate().getTime()),
                subject,
                keyPair.getPublic()
        );
        x509CertificateManager.getCertificateManager().setCertificateBuilder(certificateBuilder);
        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(keyPair.getPrivate());
        X509Certificate clientCertificate = new JcaX509CertificateConverter().getCertificate(certificateBuilder.build(signer));
        x509CertificateManager.getCertificateManager().setClientCertificate(clientCertificate);
        return new CertificateDto(x509CertificateManager.getCertificateManager().getClientCertificate());
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
      return  revocationVerifier.checkRevocationStatus(x509CertificateManager.getCertificateManager().getClientCertificate(), null).getMessage();
    }
    @GetMapping(path = GET_ALL_DISTRIBUTION_LIST)
    public List<String> allDistributionValid() throws CertificateVerificationException {
        if(!x509CertificateManager.isCertificateManagerValid()){
            return List.of("certificate is not created yet. Pls make a certificate first");
        }
        return  revocationVerifier.getCrlDistributionPoints(x509CertificateManager.getCertificateManager().getClientCertificate());
    }
    @GetMapping(path = GET_CERTIFICATE)
    public ResponseEntity<byte[]> getCertificate(@RequestParam(defaultValue = "dcsa_certificate.cert") String fileName){
        String headerValues = "attachment;filename="+fileName;
        if(!x509CertificateManager.isCertificateManagerValid()){
            HttpHeaders headers = new HttpHeaders();
            headers.add("Content-Type", "application/json; charset=utf-8");
            return new ResponseEntity<>("certificate is not created yet. Pls make a certificate first".getBytes(), headers, HttpStatus.NOT_FOUND);
        }
        byte[] bytes =  x509CertificateManager.getCertificateFile().getBytes();
        return ResponseEntity
                .ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, headerValues)
                .contentType(MediaType.APPLICATION_JSON)
                .contentLength(bytes.length)
                .body(bytes);
    }
    @PostMapping(path = USE_CERTIFICATE)
    public String useCertificate(@RequestParam("file") MultipartFile file){
        uploadService.store(file, AppProperty.uploadPath);
        return "uploaded "+file.getOriginalFilename();
    }









}
