package org.cloudfoundry.identity.uaa.util;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.openssl.PEMParser;

import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public final class PemCertificateParser {

    private PemCertificateParser() {
    }

    public static X509Certificate parseCertificate(String pemEncodedCertificate) {
        try (PEMParser pemParser = new PEMParser(new InputStreamReader(
                new ByteArrayInputStream(pemEncodedCertificate.getBytes(StandardCharsets.UTF_8))))) {
            Object object = pemParser.readObject();
            if (object instanceof X509CertificateHolder x509CertificateHolder) {
                return new JcaX509CertificateConverter().setProvider(BouncyCastleFipsProvider.PROVIDER_NAME)
                        .getCertificate(x509CertificateHolder);
            }
            throw new IllegalArgumentException("Not a PEM-encoded X.509 certificate.");
        } catch (Exception e) {
            throw new IllegalArgumentException("Unable to parse CA certificate: " + e.getMessage(), e);
        }
    }

    public static List<X509Certificate> parseCertificates(List<String> pemEncodedCertificates) {
        if (pemEncodedCertificates == null || pemEncodedCertificates.isEmpty()) {
            return List.of();
        }
        List<X509Certificate> result = new ArrayList<>(pemEncodedCertificates.size());
        for (int i = 0; i < pemEncodedCertificates.size(); i++) {
            try {
                result.add(parseCertificate(pemEncodedCertificates.get(i)));
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("CA certificate at index " + i + " is malformed: " + e.getMessage(), e);
            }
        }
        return result;
    }
}
