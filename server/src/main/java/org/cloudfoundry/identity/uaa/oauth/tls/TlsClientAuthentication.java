package org.cloudfoundry.identity.uaa.oauth.tls;

import jakarta.servlet.http.HttpServletRequest;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.openssl.PEMParser;
import org.cloudfoundry.identity.uaa.client.InvalidClientDetailsException;
import org.cloudfoundry.identity.uaa.client.TlsClientAuthConfiguration;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.io.StringReader;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Optional;
import java.util.Set;

/**
 * Validates mTLS client certificates against a configured CA and extracts
 * the certificate from the current HTTP request.
 *
 * <p>Analogous to {@link org.cloudfoundry.identity.uaa.oauth.jwt.JwtClientAuthentication}
 * but for RFC 8705 mutual-TLS client authentication.
 */
@Component
public class TlsClientAuthentication {

    /**
     * Returns the first X.509 certificate from the current request's
     * {@code jakarta.servlet.request.X509Certificate} attribute
     * (populated by the ClientCertificateMapper filter).
     *
     * @return the client certificate, or {@code null} if none is present
     */
    public X509Certificate getCertificateFromRequest() {
        X509Certificate[] chain = getCertificateChainFromRequest();
        return (chain != null && chain.length > 0) ? chain[0] : null;
    }

    /**
     * Returns the full X.509 certificate chain from the current request's
     * {@code jakarta.servlet.request.X509Certificate} attribute
     * (populated by the ClientCertificateMapper filter).
     * Index 0 is the end-entity (leaf) certificate.
     *
     * @return the client certificate chain, or {@code null} if none is present
     */
    public X509Certificate[] getCertificateChainFromRequest() {
        ServletRequestAttributes attrs =
                (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (attrs == null) {
            return null;
        }
        HttpServletRequest request = attrs.getRequest();
        X509Certificate[] certs = (X509Certificate[])
                request.getAttribute("jakarta.servlet.request.X509Certificate");
        return (certs != null && certs.length > 0) ? certs : null;
    }

    /**
     * Validates {@code clientCert} against the trusted CA PEM configured in {@code config}
     * using PKIX path validation.
     * For chains with intermediates, prefer
     * {@link #validateClientCert(X509Certificate[], TlsClientAuthConfiguration)}.
     *
     * @param clientCert the certificate presented by the client, may be {@code null}
     * @param config     the per-client TLS configuration, may be {@code null}
     * @return {@code Optional.of(clientCert)} when validation succeeds;
     *         {@code Optional.empty()} when cert or config is absent
     * @throws InvalidClientDetailsException if the CA PEM is malformed or the cert chain is invalid
     */
    public Optional<X509Certificate> validateClientCert(
            X509Certificate clientCert, TlsClientAuthConfiguration config) {
        return validateClientCert(
                clientCert != null ? new X509Certificate[]{clientCert} : null, config);
    }

    /**
     * Validates a full certificate chain against the trusted CA PEM configured in {@code config}
     * using PKIX path validation. Supports chains that include intermediate CAs.
     *
     * @param chain  the full certificate chain (index 0 = end-entity), may be {@code null}
     * @param config the per-client TLS configuration, may be {@code null}
     * @return {@code Optional.of(chain[0])} when validation succeeds;
     *         {@code Optional.empty()} when chain or config is absent
     * @throws InvalidClientDetailsException if the CA PEM is malformed or the cert chain is invalid
     */
    public Optional<X509Certificate> validateClientCert(
            X509Certificate[] chain, TlsClientAuthConfiguration config) {

        if (chain == null || chain.length == 0 || !TlsClientAuthConfiguration.isConfigured(config)) {
            return Optional.empty();
        }

        try {
            X509Certificate caCert = parsePemCertificate(config.getTrustedCaPem());

            TrustAnchor anchor = new TrustAnchor(caCert, null);
            PKIXParameters params = new PKIXParameters(Set.of(anchor));
            params.setRevocationEnabled(false);

            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            var certPath = cf.generateCertPath(Arrays.asList(chain));

            CertPathValidator validator = CertPathValidator.getInstance("PKIX");
            validator.validate(certPath, params);

            return Optional.of(chain[0]);

        } catch (CertPathValidatorException e) {
            throw new InvalidClientDetailsException(
                    "tls_client_auth: certificate chain validation failed: " + e.getMessage());
        } catch (Exception e) {
            throw new InvalidClientDetailsException(
                    "tls_client_auth: CA configuration error: " + e.getMessage());
        }
    }

    private static X509Certificate parsePemCertificate(String pem) throws Exception {
        try (PEMParser parser = new PEMParser(new StringReader(pem))) {
            Object obj = parser.readObject();
            if (!(obj instanceof X509CertificateHolder holder)) {
                throw new IllegalArgumentException(
                        obj == null
                                ? "No PEM object found in tls-client-auth-ca"
                                : "PEM object is not a certificate: " + obj.getClass().getSimpleName());
            }
            return new JcaX509CertificateConverter()
                    .setProvider(BouncyCastleFipsProvider.PROVIDER_NAME)
                    .getCertificate(holder);
        }
    }
}
