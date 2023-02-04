package org.dcsa.ctk.ebl.controller;

import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.dcsa.ctk.ebl.domain.CertificateInfo;
import org.dcsa.ctk.ebl.dto.CertificateDto;
import org.dcsa.ctk.ebl.service.X509CertificateManager;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import static org.dcsa.ctk.ebl.controller.CertificateController.ROOT_URL;

@RestController
@RequestMapping(value = ROOT_URL)
public class CsrRequestController {

    private final X509CertificateManager x509CertificateManager;

    public CsrRequestController(X509CertificateManager x509CertificateManager) {
        this.x509CertificateManager = x509CertificateManager;
    }

    @PostMapping("/generate-certificate")
    public CertificateDto  generateCertificate(@RequestBody CertificateInfo certificateInfo) throws Exception {
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
}