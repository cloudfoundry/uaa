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
        return parseCertificateChain(pemEncodedCertificate).get(0);
    }

    /**
     * Parses every PEM-encoded X.509 certificate found in the given string, so a caller may pass
     * either a single certificate or a full chain (leaf, intermediates, root) concatenated together.
     */
    public static List<X509Certificate> parseCertificateChain(String pemEncodedCertificates) {
        if (pemEncodedCertificates == null || pemEncodedCertificates.isBlank()) {
            throw new IllegalArgumentException("CA certificate must not be null or blank.");
        }
        List<X509Certificate> certificates = new ArrayList<>();
        try (PEMParser pemParser = new PEMParser(new InputStreamReader(
                new ByteArrayInputStream(pemEncodedCertificates.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8))) {
            Object object;
            while ((object = pemParser.readObject()) != null) {
                if (!(object instanceof X509CertificateHolder x509CertificateHolder)) {
                    throw new IllegalArgumentException("Not a PEM-encoded X.509 certificate.");
                }
                certificates.add(new JcaX509CertificateConverter().setProvider(BouncyCastleFipsProvider.PROVIDER_NAME)
                        .getCertificate(x509CertificateHolder));
            }
        } catch (IllegalArgumentException e) {
            // rethrow as-is so callers see our own validation message, rather than letting the
            // catch below wrap it a second time into a nested "Unable to parse..." message
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("Unable to parse CA certificate: " + e.getMessage(), e);
        }
        if (certificates.isEmpty()) {
            throw new IllegalArgumentException("Not a PEM-encoded X.509 certificate.");
        }
        return certificates;
    }

    public static List<X509Certificate> parseCertificates(List<String> pemEncodedCertificates) {
        if (pemEncodedCertificates == null || pemEncodedCertificates.isEmpty()) {
            return List.of();
        }
        List<X509Certificate> result = new ArrayList<>(pemEncodedCertificates.size());
        for (int i = 0; i < pemEncodedCertificates.size(); i++) {
            try {
                result.addAll(parseCertificateChain(pemEncodedCertificates.get(i)));
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("CA certificate at index " + i + " is malformed: " + e.getMessage(), e);
            }
        }
        return result;
    }
}
