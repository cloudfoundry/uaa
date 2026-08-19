package org.cloudfoundry.identity.uaa.oauth.tls;

import jakarta.servlet.http.HttpServletRequest;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.openssl.PEMParser;
import org.cloudfoundry.identity.uaa.client.InvalidClientDetailsException;
import org.cloudfoundry.identity.uaa.client.TlsClientAuthConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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

    private static final Logger logger = LoggerFactory.getLogger(TlsClientAuthentication.class);

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
     * Returns {@code true} when any certificate derived from the {@code X-Forwarded-Client-Cert}
     * header is present on the current request, regardless of whether it is trustworthy. This is a
     * cheap, non-trust-deciding presence check intended as an early exit before resolving a client's
     * {@link TlsClientAuthConfiguration} (which may require a database lookup) -- it does not grant or
     * imply any authorization by itself, since any caller (trusted or not) that sets the header will
     * cause the servlet container to populate this attribute.
     */
    public boolean hasCertificateFromRequest() {
        ServletRequestAttributes attrs =
                (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (attrs == null) {
            return false;
        }
        Object certs = attrs.getRequest().getAttribute("jakarta.servlet.request.X509Certificate");
        return certs instanceof X509Certificate[] arr && arr.length > 0;
    }

    /**
     * Returns the first X.509 certificate from the current request that is trustworthy for
     * {@code clientConfig} -- i.e. only when {@link #isCertificateFromTrustedProxy(TlsClientAuthConfiguration)}
     * is {@code true} for this client's configuration.
     *
     * @return the client certificate, or {@code null} if none is present or not from a trusted proxy
     */
    public X509Certificate getCertificateFromRequest(TlsClientAuthConfiguration clientConfig) {
        X509Certificate[] chain = getCertificateChainFromRequest(clientConfig);
        return (chain != null && chain.length > 0) ? chain[0] : null;
    }

    /**
     * Returns the full X.509 certificate chain from the current request's
     * {@code jakarta.servlet.request.X509Certificate} attribute (populated by the
     * {@code ClientCertificateMapper} filter), but only when
     * {@link #isCertificateFromTrustedProxy(TlsClientAuthConfiguration)} is {@code true} for
     * {@code clientConfig} -- i.e. only when the genuine TLS-handshake peer presented a certificate
     * signed by this specific client's {@code tls-client-auth-trusted-proxy-ca}. This prevents a direct
     * caller (bypassing the Gorouter) from having a self-supplied {@code X-Forwarded-Client-Cert}
     * header trusted. Index 0 is the end-entity (leaf) certificate.
     *
     * @return the client certificate chain, or {@code null} if none is present or not from a trusted proxy
     */
    public X509Certificate[] getCertificateChainFromRequest(TlsClientAuthConfiguration clientConfig) {
        if (!isCertificateFromTrustedProxy(clientConfig)) {
            return null;
        }
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
     * Returns {@code true} only when the genuine TLS-handshake peer certificate captured by
     * {@link RawPeerCertificateCaptureFilter} (the certificate the immediate TCP peer actually
     * presented during the TLS handshake -- distinct from any certificate derived from the
     * {@code X-Forwarded-Client-Cert} header) validates against {@code clientConfig}'s
     * {@code tls-client-auth-trusted-proxy-ca}.
     *
     * <p>Scoped per-client (like {@code tls-client-auth-ca}) rather than a single global CA: the value
     * is stored in {@code additionalInformation} and is therefore API-mutable at runtime. The Tomcat
     * connector (see {@code MtlsClientAuthTomcatCustomizer}) performs no CA validation at the TLS layer
     * at all ({@code certificateVerification=optionalNoCA}), so there is no static allowlist that could
     * drift out of sync with this per-client value.
     *
     * @return {@code false} if {@code clientConfig} is {@code null}, has no
     *         {@code tls-client-auth-trusted-proxy-ca} configured, or there is no current request or no
     *         captured peer certificate
     */
    public boolean isCertificateFromTrustedProxy(TlsClientAuthConfiguration clientConfig) {
        String trustedProxyCaPem = clientConfig != null ? clientConfig.getTrustedProxyCaPem() : null;
        if (trustedProxyCaPem == null || trustedProxyCaPem.isBlank()) {
            return false;
        }
        ServletRequestAttributes attrs =
                (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (attrs == null) {
            return false;
        }
        Object raw = attrs.getRequest()
                .getAttribute(RawPeerCertificateCaptureFilter.RAW_PEER_CERTIFICATE_ATTRIBUTE);
        if (!(raw instanceof X509Certificate[] peerChain) || peerChain.length == 0) {
            return false;
        }
        try {
            X509Certificate caCert = parsePemCertificate(trustedProxyCaPem);
            return validateCertPath(peerChain, caCert).isPresent();
        } catch (Exception e) {
            logger.warn("isCertificateFromTrustedProxy: peer certificate did not validate against "
                    + "tls-client-auth-trusted-proxy-ca: {}", e.getMessage());
            return false;
        }
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
            return validateCertPath(chain, caCert);
        } catch (CertPathValidatorException e) {
            throw new InvalidClientDetailsException(
                    "tls_client_auth: certificate chain validation failed: " + e.getMessage());
        } catch (Exception e) {
            throw new InvalidClientDetailsException(
                    "tls_client_auth: CA configuration error: " + e.getMessage());
        }
    }

    /**
     * Validates {@code chain} against {@code caCert} using PKIX path validation, without requiring any
     * per-client {@link TlsClientAuthConfiguration}. Shared by {@link #validateClientCert} and
     * {@link #isCertificateFromTrustedProxy}.
     *
     * @return {@code Optional.of(chain[0])} when validation succeeds
     * @throws CertPathValidatorException if the chain does not validate against {@code caCert}
     * @throws Exception if {@code caCert} or the PKIX machinery is misconfigured
     */
    private static Optional<X509Certificate> validateCertPath(X509Certificate[] chain, X509Certificate caCert)
            throws Exception {
        TrustAnchor anchor = new TrustAnchor(caCert, null);
        PKIXParameters params = new PKIXParameters(Set.of(anchor));
        params.setRevocationEnabled(false);

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        var certPath = cf.generateCertPath(Arrays.asList(chain));

        CertPathValidator validator = CertPathValidator.getInstance("PKIX");
        validator.validate(certPath, params);

        return Optional.of(chain[0]);
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
