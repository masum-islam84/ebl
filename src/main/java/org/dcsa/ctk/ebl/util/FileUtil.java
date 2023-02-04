package org.dcsa.ctk.ebl.util;

import org.springframework.core.io.ClassPathResource;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Objects;

public class FileUtil {

    static public final String ROOT_CERTIFICATE = "root-key/rootCA.crt";
    static public final String ROOT_PRIVATE_KEY = "root-key/rootCA.key";
    static public final String ROOT_JAVA_KEY_STORE = "root-key/rootCA.jks";
    static public final String ROOT_CERTIFICATE_PASSWORD = "password";
    static public final String ROOT_CERTIFICATE_ALIAS= "root";

    static public void loadRootCertAndPrivateKey(){
        try {
            ClassPathResource resource = new ClassPathResource(ROOT_JAVA_KEY_STORE);
            FileInputStream is = new FileInputStream(Objects.requireNonNull(resource.getFilename()));
            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            keystore.load(is, ROOT_CERTIFICATE_PASSWORD.toCharArray());
            PrivateKey rootPrivateKey = (PrivateKey) keystore.getKey(ROOT_CERTIFICATE_ALIAS, ROOT_CERTIFICATE_PASSWORD.toCharArray());
            X509Certificate rootCertificate = (X509Certificate) keystore.getCertificate(ROOT_CERTIFICATE_ALIAS);
        } catch (IOException | UnrecoverableKeyException | CertificateException | KeyStoreException |
                 NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }


}
