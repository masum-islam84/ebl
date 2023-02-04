package org.dcsa.ctk.ebl.service;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class CSRGenerator {

    public static void generateCSR() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDSA", "BC");
        ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("secp256r1");
        keyPairGenerator.initialize(ecGenParameterSpec);

        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        X500NameBuilder nameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
        nameBuilder.addRDN(BCStyle.CN, "your_common_name");
        nameBuilder.addRDN(BCStyle.O, "your_organization");
        nameBuilder.addRDN(BCStyle.OU, "your_organization_unit");
        nameBuilder.addRDN(BCStyle.L, "your_location");
        nameBuilder.addRDN(BCStyle.ST, "your_state");
        nameBuilder.addRDN(BCStyle.C, "your_country_code");

        final Date start = new Date();
        final Date until = Date.from(LocalDate.now().plus(365, ChronoUnit.DAYS).atStartOfDay().toInstant(ZoneOffset.UTC));

/*
        X509v3CertificateBuilder certificateBuilder = new X509v3CertificateBuilder(
                nameBuilder.build(),
                new BigInteger(10, new SecureRandom()),
                start,
                until,
                nameBuilder.build(),
                keyPair.getPublic()
        );
*/

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.getPrivate());
      //  X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(certificateBuilder.build(signer));

        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(keyPair.getPrivate());
      //  signature.update(certificate.getEncoded());

        System.out.println("CSR: " + signature);
    }
}
