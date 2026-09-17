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

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.security.auth.x500.X500Principal;
import java.io.StringReader;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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

    private static final String XFCC_HEADER = "X-Forwarded-Client-Cert";

    /**
     * Returns {@code true} when any certificate is present on the current request under the
     * standard {@code jakarta.servlet.request.X509Certificate} attribute -- whether that attribute
     * holds a certificate derived from the {@code X-Forwarded-Client-Cert} header, or (when no XFCC
     * header was sent) the raw TLS-handshake peer certificate -- regardless of whether it is
     * trustworthy. This is a cheap, non-trust-deciding presence check intended as an early exit before
     * resolving a client's {@link TlsClientAuthConfiguration} (which may require a database lookup) --
     * it does not grant or imply any authorization by itself, since any caller (trusted or not) that
     * sets the header will cause the servlet container to populate this attribute.
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
     * Returns the full X.509 certificate chain the current request should be authenticated with,
     * per {@code clientConfig}'s configured trust model:
     *
     * <ul>
     *   <li>If {@code clientConfig} has no {@code tls-client-auth-trusted-proxy-ca} configured,
     *       this client is direct-connection-only: always returns the genuine TLS-handshake peer
     *       certificate chain (captured by {@link RawPeerCertificateCaptureFilter}), ignoring any
     *       {@code X-Forwarded-Client-Cert} header entirely.</li>
     *   <li>If {@code tls-client-auth-trusted-proxy-ca} is configured, this client is
     *       proxy-only: requires an {@code X-Forwarded-Client-Cert} header to be present and
     *       {@link #isCertificateFromTrustedProxy(TlsClientAuthConfiguration)} to be {@code true}
     *       (the genuine TLS peer -- e.g. the Gorouter -- must validate against the configured
     *       proxy CA) before returning the header-derived certificate chain from the standard
     *       {@code jakarta.servlet.request.X509Certificate} attribute. Additionally, the standard
     *       attribute's certificate chain must differ from the raw peer certificate chain
     *       captured by {@link RawPeerCertificateCaptureFilter}: the third-party
     *       {@code ClientCertificateMapper} servlet filter does not clear or null the standard
     *       attribute when it fails to parse the XFCC header -- it simply never replaces it,
     *       leaving the genuine raw peer certificate (e.g. the proxy's own certificate) in place.
     *       If the two attributes are identical, the mapper did not actually run successfully,
     *       and the request is rejected rather than treating the proxy's own certificate as the
     *       client's.</li>
     * </ul>
     *
     * <p>The two modes are mutually exclusive per client: a client cannot accept both a direct
     * connection and a proxy-forwarded one. An operator needing both registers two separate UAA
     * clients. Index 0 of the returned chain is the end-entity (leaf) certificate.
     *
     * @return the client certificate chain, or {@code null} if none is present or the request
     *         doesn't match this client's configured trust model
     */
    public X509Certificate[] getCertificateChainFromRequest(TlsClientAuthConfiguration clientConfig) {
        ServletRequestAttributes attrs =
                (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (attrs == null) {
            return null;
        }
        HttpServletRequest request = attrs.getRequest();
        boolean trustedProxyConfigured = clientConfig != null
                && clientConfig.getTrustedProxyCaPem() != null
                && !clientConfig.getTrustedProxyCaPem().isBlank();

        if (!trustedProxyConfigured) {
            // Direct-connection-only client: always use the genuine TLS-handshake peer
            // certificate, regardless of any X-Forwarded-Client-Cert header -- this client's
            // trust model has no proxy in it at all.
            X509Certificate[] rawPeerCerts = (X509Certificate[])
                    request.getAttribute(RawPeerCertificateCaptureFilter.RAW_PEER_CERTIFICATE_ATTRIBUTE);
            return (rawPeerCerts != null && rawPeerCerts.length > 0) ? rawPeerCerts : null;
        }

        // Proxy-only client: require the XFCC header to actually be present -- a direct
        // connection (no header) is always rejected, even if its own certificate would validate
        // against tls-client-auth-trusted-proxy-ca -- plus the genuine peer (the proxy) must
        // validate against it.
        String xfccHeader = request.getHeader(XFCC_HEADER);
        if (xfccHeader == null || xfccHeader.isBlank() || !isCertificateFromTrustedProxy(clientConfig)) {
            return null;
        }
        X509Certificate[] certs = (X509Certificate[])
                request.getAttribute("jakarta.servlet.request.X509Certificate");
        if (certs == null || certs.length == 0) {
            return null;
        }
        // Guard against ClientCertificateMapper silently failing to parse the XFCC header: it
        // does not clear/null the standard attribute on a parse failure, it simply never replaces
        // it, leaving the genuine raw peer certificate (e.g. the proxy's own certificate) in
        // place. If the standard attribute is unchanged from the raw peer capture, the mapper did
        // not actually run successfully -- treating it as the client's certificate would let the
        // proxy authenticate as the client whenever the proxy's own certificate happens to
        // validate against this client's tls-client-auth-ca.
        X509Certificate[] rawPeerCerts = (X509Certificate[])
                request.getAttribute(RawPeerCertificateCaptureFilter.RAW_PEER_CERTIFICATE_ATTRIBUTE);
        if (Arrays.equals(certs, rawPeerCerts)) {
            logger.warn("getCertificateChainFromRequest: X-Forwarded-Client-Cert header present and peer "
                    + "validated as trusted proxy, but the standard X509Certificate attribute was unchanged "
                    + "from the raw peer certificate -- ClientCertificateMapper likely failed to parse the "
                    + "XFCC header; rejecting rather than treating the proxy's own certificate as the client's");
            return null;
        }
        return certs;
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
     * <p>Like {@link #validateClientCert(X509Certificate[], TlsClientAuthConfiguration)}, PKIX path
     * validation alone does not enforce that the validated peer leaf is actually meant to be used as a
     * TLS client authentication credential -- since the connector's trust manager accepts any certificate
     * at the TLS layer, a CA certificate or a certificate whose Key Usage/Extended Key Usage extensions
     * explicitly exclude client authentication could otherwise still be accepted as the trusted proxy's
     * own credential. This method therefore also applies {@link #validateEndEntityConstraints} to the
     * validated peer leaf, returning {@code false} (via the catch-all below) if it fails.
     *
     * @return {@code false} if {@code clientConfig} is {@code null}, has no
     *         {@code tls-client-auth-trusted-proxy-ca} configured, there is no current request or no
     *         captured peer certificate, the peer certificate does not validate against the configured
     *         proxy CA, or the validated peer leaf fails an end-entity constraint check
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
            Optional<X509Certificate> validated = validateCertPath(peerChain, caCert);
            if (validated.isPresent()) {
                validateEndEntityConstraints(validated.get());
            }
            return validated.isPresent();
        } catch (Exception e) {
            logger.warn("isCertificateFromTrustedProxy: peer certificate did not validate against "
                    + "tls-client-auth-trusted-proxy-ca: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Extracts claim-name -> value pairs from {@code cert}'s subject fields per {@code config}'s
     * {@code tls-client-auth-claim-mappings}. Shared by {@link MtlsClaimsEnhancer} (to build JWT
     * claims) and {@link #certificateSatisfiesRequiredClaims} (to enforce
     * {@code tls-client-auth-required-claims} at authentication time, before any claim is built).
     *
     * @return an empty map if {@code cert} or {@code config} is {@code null}, or if
     *         {@code config} has no {@code tls-client-auth-claim-mappings} configured
     */
    public Map<String, String> extractClaimMappingValues(X509Certificate cert, TlsClientAuthConfiguration config) {
        if (cert == null || config == null || config.getClaimMappings() == null) {
            return Map.of();
        }
        X500Principal subject = cert.getSubjectX500Principal();
        String dn = subject.getName(X500Principal.RFC2253);
        String cn = extractRdnValue(dn, "CN");
        List<String> ous = extractOus(dn);

        Map<String, String> vars = new HashMap<>();
        for (TlsClientAuthConfiguration.ClaimMapping mapping : config.getClaimMappings()) {
            String value = switch (mapping.getField()) {
                case "subject_cn" -> cn;
                case "subject_ou" -> matchFirstOu(ous, mapping.getPattern());
                case "subject_o"  -> extractRdnValue(dn, "O");
                default -> null;
            };
            if (value != null && !value.isBlank()) {
                vars.put(mapping.getClaim(), value);
            }
        }
        return vars;
    }

    /**
     * Returns {@code true} when {@code config} has no {@code tls-client-auth-required-claims}
     * configured (unrestricted, current behavior), or when every required claim name maps to
     * exactly the required value once extracted from {@code cert} via
     * {@code tls-client-auth-claim-mappings}. This is what lets a client be scoped to e.g. a
     * specific CF space/org/app -- closing the gap where any certificate chaining to a shared CA
     * could otherwise authenticate as any client that trusts that CA.
     */
    public boolean certificateSatisfiesRequiredClaims(X509Certificate cert, TlsClientAuthConfiguration config) {
        if (config == null || config.getRequiredClaims() == null || config.getRequiredClaims().isEmpty()) {
            return true;
        }
        Map<String, String> vars = extractClaimMappingValues(cert, config);
        for (Map.Entry<String, String> required : config.getRequiredClaims().entrySet()) {
            if (!required.getValue().equals(vars.get(required.getKey()))) {
                logger.debug("certificateSatisfiesRequiredClaims: required claim '{}' did not match "
                        + "(expected '{}', extracted '{}')",
                        required.getKey(), required.getValue(), vars.get(required.getKey()));
                return false;
            }
        }
        return true;
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
     * <p>PKIX path validation alone only proves the presented chain structurally links to the
     * configured trust anchor -- it does not enforce that the end-entity (leaf) certificate,
     * {@code chain[0]}, is actually meant to be used as a TLS client authentication credential.
     * Because the connector accepts this call without any TLS-layer CA validation of its own
     * (see {@code MtlsClientAuthTomcatCustomizer}, {@code certificateVerification=optionalNoCA}),
     * this method additionally rejects {@code chain[0]} (after PKIX validation succeeds) when it:
     * <ul>
     *   <li>is itself a CA certificate (a {@code BasicConstraints} extension with {@code CA=true}),</li>
     *   <li>has a Key Usage extension present that does not permit {@code digitalSignature}, or</li>
     *   <li>has an Extended Key Usage extension present that does not include
     *       {@code id-kp-clientAuth} or {@code anyExtendedKeyUsage}.</li>
     * </ul>
     * These checks only reject when an extension is present and explicitly excludes client
     * authentication -- an absent extension imposes no restriction (RFC 5280), preserving
     * backward compatibility with CAs that don't set these extensions at all.
     *
     * @param chain  the full certificate chain (index 0 = end-entity), may be {@code null}
     * @param config the per-client TLS configuration, may be {@code null}
     * @return {@code Optional.of(chain[0])} when validation succeeds;
     *         {@code Optional.empty()} when chain or config is absent
     * @throws InvalidClientDetailsException if the CA PEM is malformed, the cert chain is invalid,
     *         or {@code chain[0]} fails an end-entity constraint check
     */
    public Optional<X509Certificate> validateClientCert(
            X509Certificate[] chain, TlsClientAuthConfiguration config) {

        if (chain == null || chain.length == 0 || !TlsClientAuthConfiguration.isConfigured(config)) {
            return Optional.empty();
        }

        try {
            X509Certificate caCert = parsePemCertificate(config.getTrustedCaPem());
            Optional<X509Certificate> validated = validateCertPath(chain, caCert);
            if (validated.isPresent()) {
                validateEndEntityConstraints(validated.get());
            }
            return validated;
        } catch (CertPathValidatorException e) {
            throw new InvalidClientDetailsException(
                    "tls_client_auth: certificate chain validation failed: " + e.getMessage());
        } catch (Exception e) {
            throw new InvalidClientDetailsException(
                    "tls_client_auth: CA configuration error: " + e.getMessage());
        }
    }

    /**
     * Extended Key Usage OID for TLS client authentication ({@code id-kp-clientAuth}, RFC 5280 §4.2.1.12).
     */
    private static final String EKU_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2";

    /**
     * Extended Key Usage OID meaning "any extended key usage is acceptable" (RFC 5280 §4.2.1.12).
     */
    private static final String EKU_ANY = "2.5.29.37.0";

    /**
     * Rejects {@code leaf} when it carries an extension that explicitly signals it is unsuitable
     * as a TLS client authentication credential. See {@link #validateClientCert(X509Certificate[],
     * TlsClientAuthConfiguration)} for the full rationale. Absent extensions are never rejected.
     *
     * @throws CertPathValidatorException if {@code leaf} is itself a CA certificate, its Key
     *         Usage extension (if present) does not permit {@code digitalSignature}, or its
     *         Extended Key Usage extension (if present, or unparsable) does not include
     *         {@code id-kp-clientAuth} or {@code anyExtendedKeyUsage}
     */
    private static void validateEndEntityConstraints(X509Certificate leaf) throws CertPathValidatorException {
        if (leaf.getBasicConstraints() != -1) {
            throw new CertPathValidatorException(
                    "presented end-entity certificate is itself a CA certificate");
        }

        boolean[] keyUsage = leaf.getKeyUsage();
        if (keyUsage != null && (keyUsage.length < 1 || !keyUsage[0])) {
            throw new CertPathValidatorException(
                    "presented end-entity certificate's Key Usage extension does not permit digitalSignature");
        }

        List<String> extendedKeyUsage;
        try {
            extendedKeyUsage = leaf.getExtendedKeyUsage();
        } catch (java.security.cert.CertificateParsingException e) {
            throw new CertPathValidatorException(
                    "presented end-entity certificate has an unparsable Extended Key Usage extension: "
                            + e.getMessage());
        }
        if (extendedKeyUsage != null
                && !extendedKeyUsage.contains(EKU_CLIENT_AUTH)
                && !extendedKeyUsage.contains(EKU_ANY)) {
            throw new CertPathValidatorException(
                    "presented end-entity certificate's Extended Key Usage extension does not include "
                            + "clientAuth or anyExtendedKeyUsage");
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

    /**
     * Parses an RFC 2253 DN string into its RDNs, ordered most-specific-first
     * (i.e. matching the left-to-right order of the original DN string).
     *
     * <p>{@link LdapName#getRdns()} returns RDNs least-specific-first (root/rightmost
     * component at index 0), so the list is reversed here. Using {@link LdapName} instead
     * of a naive {@code dn.split(",")} correctly handles backslash-escaped commas/quotes
     * within attribute values (RFC 2253 §2.4), which a plain string split would mis-parse.
     * Returns an empty list if {@code dn} cannot be parsed as a valid DN.
     */
    private static List<Rdn> parseRdnsMostSpecificFirst(String dn) {
        try {
            List<Rdn> rdns = new ArrayList<>(new LdapName(dn).getRdns());
            Collections.reverse(rdns);
            return rdns;
        } catch (NamingException e) {
            return List.of();
        }
    }

    /**
     * Returns one value of the given attribute {@code type} (e.g. {@code "CN"}) from an RDN,
     * including multi-valued RDNs (attributes joined by {@code +}). Attribute type matching
     * is case-insensitive, per LDAP semantics. Where an RDN contains repeated AVAs of the same
     * type, the chosen value follows provider enumeration order. Returns {@code null} if not present.
     */
    private static String rdnAttributeValue(Rdn rdn, String type) {
        List<String> values = rdnAttributeValues(rdn, type);
        return values.isEmpty() ? null : values.get(0);
    }

    /**
     * Returns every value of an attribute from an RDN. A multi-valued RDN can contain the same
     * attribute type more than once, as Diego instance identity certificates do for OU.
     */
    private static List<String> rdnAttributeValues(Rdn rdn, String type) {
        List<String> values = new ArrayList<>();
        try {
            NamingEnumeration<? extends Attribute> attrs = rdn.toAttributes().getAll();
            while (attrs.hasMore()) {
                Attribute attr = attrs.next();
                if (attr.getID().equalsIgnoreCase(type)) {
                    NamingEnumeration<?> attributeValues = attr.getAll();
                    while (attributeValues.hasMore()) {
                        Object value = attributeValues.next();
                        if (value != null) {
                            values.add(value.toString());
                        }
                    }
                }
            }
        } catch (NamingException e) {
            // fall through to values collected so far
        }
        return values;
    }

    /**
     * Extracts the value of a single-valued RDN attribute (e.g. {@code "CN"}) from a RFC 2253
     * DN string. Handles multi-valued RDNs (attributes joined by {@code +}).
     * Returns {@code null} if no matching RDN is found.
     */
    private static String extractRdnValue(String dn, String type) {
        for (Rdn rdn : parseRdnsMostSpecificFirst(dn)) {
            String value = rdnAttributeValue(rdn, type);
            if (value != null) {
                return value;
            }
        }
        return null;
    }

    /**
     * Collects all matching OU AVAs from an RFC 2253 DN string, including multi-valued RDNs
     * (attributes joined by {@code +}).
     */
    private static List<String> extractOus(String dn) {
        List<String> ous = new ArrayList<>();
        for (Rdn rdn : parseRdnsMostSpecificFirst(dn)) {
            ous.addAll(rdnAttributeValues(rdn, "OU"));
        }
        return ous;
    }

    /**
     * Returns the first captured group from the first OU that matches {@code patternStr}.
     * When {@code patternStr} is null or blank, returns the first collected OU value verbatim;
     * selection among repeated AVAs follows collected/provider order. Use a pattern to select a
     * specific value.
     */
    private static String matchFirstOu(List<String> ous, String patternStr) {
        if (patternStr == null || patternStr.isBlank()) {
            return ous.isEmpty() ? null : ous.get(0);
        }
        Pattern pat = Pattern.compile(patternStr);
        for (String ou : ous) {
            Matcher m = pat.matcher(ou);
            if (m.matches() && m.groupCount() >= 1) {
                return m.group(1);
            }
        }
        return null;
    }
}
