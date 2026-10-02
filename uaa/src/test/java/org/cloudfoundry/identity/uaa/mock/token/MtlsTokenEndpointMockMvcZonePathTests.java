package org.cloudfoundry.identity.uaa.mock.token;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.client.TlsClientAuthConfiguration;
import org.cloudfoundry.identity.uaa.extensions.EnabledIfZonePathsEnabled;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.mock.util.ZoneResolutionMode;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.oauth.tls.RawPeerCertificateCaptureFilter;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.ZoneContextPathSessionFilter;
import org.cloudfoundry.identity.uaa.zone.ZonePathContextRewritingFilter;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.http.HttpMethod;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import tools.jackson.core.type.TypeReference;

import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_CLIENT_CREDENTIALS;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.config.BeanIds.SPRING_SECURITY_FILTER_CHAIN;

/**
 * Identity-zone isolation for the RFC 8705 mTLS token endpoint, exercised through both ways a zone
 * can be addressed -- {@code {subdomain}.localhost} and the {@code /z/{subdomain}} path prefix.
 *
 * <p>UAA is multi-tenant, so the question these tests answer is not "does mTLS work" but "does one
 * tenant's mTLS configuration stay inside that tenant". The feature's per-client settings --
 * {@code tls-client-auth-ca}, the subject binding, the claim mappings, the trusted proxy CA -- all
 * live in client details, and clients are zone-scoped rows; the trust decision therefore hinges
 * entirely on the lookup in {@code MtlsClaimsEnhancer} resolving against the <em>current</em> zone.
 * That lookup uses the one-argument {@code loadClientByClientId}, which delegates to
 * {@code IdentityZoneManager.getCurrentIdentityZoneId()}, so correctness depends on zone context
 * being established before client authentication runs -- for both addressing modes.
 *
 * <p>Both modes matter independently. The mTLS filters
 * ({@link RawPeerCertificateCaptureFilter#isMtlsTokenPath}) match on the request's
 * <em>effective servlet path</em>, i.e. after {@link ZonePathContextRewritingFilter} has stripped a
 * {@code /z/{subdomain}} prefix. A path-matching regression would therefore show up only in
 * {@code ZONE_PATH} mode, and one that skipped certificate capture would fail closed while one that
 * skipped the availability guard would fail open.
 *
 * <p>The only genuinely global setting is {@code uaa.mtls-enabled}, which is deployment topology
 * (it configures the Tomcat connector to request client certificates at all); it is enabled here so
 * the endpoint exists in every zone, which is exactly the condition under which tenant bleed would
 * be observable.
 */
@DefaultTestContext
@TestPropertySource(properties = {"uaa.mtls-enabled=true"})
@EnabledIfZonePathsEnabled
class MtlsTokenEndpointMockMvcZonePathTests extends AbstractTokenMockMvcTests {

    private static final String MTLS_PATH = "/oauth/mtls/token";
    private static final String DISCOVERY_PATH = "/.well-known/openid-configuration";

    /** Stands in for tenant A's certificate authority. */
    private static KeyPair zoneACaKeyPair;
    private static X500Name zoneACaSubject;
    private static X509Certificate zoneACaCert;

    /** Stands in for tenant B's, entirely unrelated, certificate authority. */
    private static KeyPair zoneBCaKeyPair;
    private static X500Name zoneBCaSubject;
    private static X509Certificate zoneBCaCert;

    @Qualifier(SPRING_SECURITY_FILTER_CHAIN)
    @Autowired
    FilterChainProxy securityFilterChain;

    @Qualifier(ZonePathContextRewritingFilter.REGISTRATION_BEAN_NAME)
    @Autowired
    FilterRegistrationBean<ZonePathContextRewritingFilter> zonePathFilterRegistration;

    @Qualifier(ZoneContextPathSessionFilter.REGISTRATION_BEAN_NAME)
    @Autowired
    FilterRegistrationBean<ZoneContextPathSessionFilter> zoneContextPathSessionFilterRegistration;

    @Qualifier("rawPeerCertificateCaptureFilter")
    @Autowired
    FilterRegistrationBean<RawPeerCertificateCaptureFilter> rawPeerCertificateCaptureFilterRegistration;

    @BeforeAll
    static void registerFipsProviderAndBuildCas() throws Exception {
        if (Security.getProvider(BouncyCastleFipsProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleFipsProvider());
        }
        zoneACaKeyPair = generateKeyPair();
        zoneACaSubject = new X500Name("CN=Zone A mTLS CA");
        zoneACaCert = signCert(zoneACaSubject, zoneACaSubject, zoneACaKeyPair.getPublic(),
                zoneACaKeyPair.getPrivate(), true);

        zoneBCaKeyPair = generateKeyPair();
        zoneBCaSubject = new X500Name("CN=Zone B mTLS CA");
        zoneBCaCert = signCert(zoneBCaSubject, zoneBCaSubject, zoneBCaKeyPair.getPublic(),
                zoneBCaKeyPair.getPrivate(), true);
    }

    /**
     * Rebuilt to include the zone-resolution filters and {@link RawPeerCertificateCaptureFilter},
     * none of which {@code DefaultTestContext} puts in the MockMvc chain. Order is load-bearing:
     * {@link ZonePathContextRewritingFilter} must rewrite {@code /z/{subdomain}} before the
     * certificate-capture filter inspects the servlet path.
     */
    @BeforeEach
    void setUpMtlsMockMvc() {
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
                .addFilter(zonePathFilterRegistration.getFilter())
                .addFilter(zoneContextPathSessionFilterRegistration.getFilter())
                .addFilter(rawPeerCertificateCaptureFilterRegistration.getFilter())
                .addFilter(securityFilterChain)
                .build();
        testClient = new TestClient(mockMvc);
    }

    // ------------------------------------------------------------------------------------
    // Group Z1 -- a tenant's mTLS client works in its own zone
    // ------------------------------------------------------------------------------------

    @Nested
    @DisplayName("Z1. an mTLS client works in the zone it belongs to")
    class OwnZone {

        @ParameterizedTest
        @EnumSource(ZoneResolutionMode.class)
        @DisplayName("issues a certificate-bound token in a non-default zone")
        void issuesTokenInNonDefaultZone(ZoneResolutionMode mode) throws Exception {
            IdentityZone zone = newZone();
            String clientId = mtlsClientInZone(zone, "z1", zoneBCaCert, "CN=z1-app");
            X509Certificate cert = leafSignedBy(zoneBCaSubject, zoneBCaKeyPair, "CN=z1-app");

            MvcResult result = perform(mtlsPost(mode, zone, clientId, cert));

            assertThat(result.getResponse().getStatus())
                    .as("a zone's own mTLS client must authenticate at that zone's endpoint. Actual: %s",
                            outcome(result))
                    .isEqualTo(200);
            Map<String, Object> claims = claimsOf(result);
            assertThat(claims.get("cnf"))
                    .as("the token must be certificate-bound per RFC 8705 section 3.1. Claims: %s", claims)
                    .isNotNull();
        }

        @ParameterizedTest
        @EnumSource(ZoneResolutionMode.class)
        @DisplayName("stamps the issuing zone's own issuer on the token")
        void tokenCarriesTheZonesOwnIssuer(ZoneResolutionMode mode) throws Exception {
            IdentityZone zone = newZone();
            String clientId = mtlsClientInZone(zone, "z1b", zoneBCaCert, "CN=z1b-app");
            X509Certificate cert = leafSignedBy(zoneBCaSubject, zoneBCaKeyPair, "CN=z1b-app");

            MvcResult result = perform(mtlsPost(mode, zone, clientId, cert));
            assertThat(result.getResponse().getStatus()).as("Actual: %s", outcome(result)).isEqualTo(200);

            Map<String, Object> claims = claimsOf(result);
            assertThat((String) claims.get("iss"))
                    .as("a token minted in a zone must not be issued under the default zone's identity. "
                            + "Claims: %s", claims)
                    .contains(zone.getSubdomain());
        }
    }

    // ------------------------------------------------------------------------------------
    // Group Z2 -- one tenant's certificate must not authenticate in another tenant's zone
    // ------------------------------------------------------------------------------------

    @Nested
    @DisplayName("Z2. mTLS client configuration does not cross zone boundaries")
    class CrossZoneIsolation {

        @ParameterizedTest
        @EnumSource(ZoneResolutionMode.class)
        @DisplayName("a client that exists only in the default zone cannot be used in another zone")
        void defaultZoneClientIsNotUsableInAnotherZone(ZoneResolutionMode mode) throws Exception {
            // This is the uaa.yml case: clients bootstrapped from configuration land in the default
            // zone, and must not become usable in every tenant's zone.
            String clientId = mtlsClientInZone(IdentityZone.getUaa(), "z2a", zoneACaCert, "CN=z2a-app");
            X509Certificate cert = leafSignedBy(zoneACaSubject, zoneACaKeyPair, "CN=z2a-app");
            IdentityZone otherZone = newZone();

            MvcResult result = perform(mtlsPost(mode, otherZone, clientId, cert));

            assertThat(result.getResponse().getStatus())
                    .as("a default-zone client must not authenticate against another zone. Actual: %s",
                            outcome(result))
                    .isNotEqualTo(200);
        }

        @ParameterizedTest
        @EnumSource(ZoneResolutionMode.class)
        @DisplayName("a client that exists only in another zone cannot be used in the default zone")
        void otherZoneClientIsNotUsableInDefaultZone(ZoneResolutionMode mode) throws Exception {
            IdentityZone zone = newZone();
            String clientId = mtlsClientInZone(zone, "z2b", zoneBCaCert, "CN=z2b-app");
            X509Certificate cert = leafSignedBy(zoneBCaSubject, zoneBCaKeyPair, "CN=z2b-app");

            MvcResult result = perform(mtlsPost(mode, null, clientId, cert));

            assertThat(result.getResponse().getStatus())
                    .as("a tenant's client must not leak into the default zone. Actual: %s", outcome(result))
                    .isNotEqualTo(200);
        }

        /**
         * The sharpest form of the question: the same {@code client_id} is registered in two zones
         * with two different CAs. Nothing about the request distinguishes the tenants except the
         * zone it is addressed to, so if the CA were resolved from anywhere other than the current
         * zone's client row -- a shared cache, a global default, the first row that matched the id
         * -- one tenant's certificate would mint the other tenant's token.
         */
        @ParameterizedTest
        @EnumSource(ZoneResolutionMode.class)
        @DisplayName("the same client_id in two zones keeps two separate CAs")
        void sameClientIdInTwoZonesKeepsSeparateCas(ZoneResolutionMode mode) throws Exception {
            String sharedClientId = "mtlsz2c" + generator.generate();
            IdentityZone zoneB = newZone();
            registerMtlsClient(IdentityZone.getUaa(), sharedClientId, zoneACaCert, "CN=shared-app");
            registerMtlsClient(zoneB, sharedClientId, zoneBCaCert, "CN=shared-app");

            X509Certificate zoneACert = leafSignedBy(zoneACaSubject, zoneACaKeyPair, "CN=shared-app");
            X509Certificate zoneBCert = leafSignedBy(zoneBCaSubject, zoneBCaKeyPair, "CN=shared-app");

            MvcResult wrongCaForZoneB = perform(mtlsPost(mode, zoneB, sharedClientId, zoneACert));
            assertThat(wrongCaForZoneB.getResponse().getStatus())
                    .as("zone A's certificate must not satisfy zone B's client of the same name. Actual: %s",
                            outcome(wrongCaForZoneB))
                    .isNotEqualTo(200);

            MvcResult wrongCaForDefaultZone = perform(mtlsPost(mode, null, sharedClientId, zoneBCert));
            assertThat(wrongCaForDefaultZone.getResponse().getStatus())
                    .as("zone B's certificate must not satisfy the default zone's client of the same name. "
                            + "Actual: %s", outcome(wrongCaForDefaultZone))
                    .isNotEqualTo(200);

            MvcResult correctCaForZoneB = perform(mtlsPost(mode, zoneB, sharedClientId, zoneBCert));
            assertThat(correctCaForZoneB.getResponse().getStatus())
                    .as("the matching certificate must still work, proving the refusals above were about "
                            + "the zone and not a broken fixture. Actual: %s", outcome(correctCaForZoneB))
                    .isEqualTo(200);
        }
    }

    // ------------------------------------------------------------------------------------
    // Group Z3 -- advertised metadata must describe the zone that was asked
    // ------------------------------------------------------------------------------------

    @Nested
    @DisplayName("Z3. discovery metadata is zone-specific")
    class DiscoveryMetadata {

        @ParameterizedTest
        @EnumSource(ZoneResolutionMode.class)
        @DisplayName("mtls_endpoint_aliases points at the requested zone, not the default zone")
        void mtlsEndpointAliasIsZoneSpecific(ZoneResolutionMode mode) throws Exception {
            IdentityZone zone = newZone();

            MvcResult result = perform(withServletPath(
                    mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.GET, DISCOVERY_PATH),
                    mode, zone.getSubdomain(), DISCOVERY_PATH).accept(APPLICATION_JSON));
            assertThat(result.getResponse().getStatus()).as("Actual: %s", outcome(result)).isEqualTo(200);

            Map<String, Object> body = JsonUtils.readValue(result.getResponse().getContentAsString(),
                    new TypeReference<Map<String, Object>>() {});
            @SuppressWarnings("unchecked")
            Map<String, String> aliases = (Map<String, String>) body.get("mtls_endpoint_aliases");

            assertThat(aliases)
                    .as("RFC 8705 section 5 metadata must be advertised when mTLS is enabled. Body: %s", body)
                    .isNotNull();
            assertThat(aliases.get("token_endpoint"))
                    .as("a tenant must be told its own mTLS endpoint; handing out the default zone's URL "
                            + "would send its clients' certificates to another tenant's endpoint. Body: %s", body)
                    .contains(zone.getSubdomain())
                    .endsWith(MTLS_PATH);
        }

        @ParameterizedTest
        @EnumSource(ZoneResolutionMode.class)
        @DisplayName("tls_client_auth and certificate-bound tokens are advertised per zone")
        void tlsClientAuthIsAdvertisedInZone(ZoneResolutionMode mode) throws Exception {
            IdentityZone zone = newZone();

            MvcResult result = perform(withServletPath(
                    mode.createRequestBuilder(zone.getSubdomain(), HttpMethod.GET, DISCOVERY_PATH),
                    mode, zone.getSubdomain(), DISCOVERY_PATH).accept(APPLICATION_JSON));

            Map<String, Object> body = JsonUtils.readValue(result.getResponse().getContentAsString(),
                    new TypeReference<Map<String, Object>>() {});

            @SuppressWarnings("unchecked")
            List<String> authMethods = (List<String>) body.get("token_endpoint_auth_methods_supported");
            assertThat(authMethods)
                    .as("Body: %s", body)
                    .contains("tls_client_auth");
            assertThat(body.get("tls_client_certificate_bound_access_tokens"))
                    .as("RFC 8705 section 3.3. Body: %s", body)
                    .isEqualTo(true);
            assertThat((String) body.get("issuer"))
                    .as("the issuer must identify the requested zone. Body: %s", body)
                    .contains(zone.getSubdomain());
        }
    }

    // ------------------------------------------------------------------------------------
    // helpers
    // ------------------------------------------------------------------------------------

    private IdentityZone newZone() throws Exception {
        String subdomain = generator.generate().toLowerCase();
        return MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext,
                IdentityZone.getUaaZoneId());
    }

    /** Registers an mTLS client in {@code zone} and strips its secret, leaving the CA as sole credential. */
    private String mtlsClientInZone(IdentityZone zone, String tag, X509Certificate ca, String subjectDn)
            throws Exception {
        String clientId = "mtls" + tag + generator.generate();
        registerMtlsClient(zone, clientId, ca, subjectDn);
        return clientId;
    }

    private void registerMtlsClient(IdentityZone zone, String clientId, X509Certificate ca, String subjectDn)
            throws Exception {
        setUpClients(clientId, "uaa.resource", "uaa.none", GRANT_TYPE_CLIENT_CREDENTIALS,
                false, null, null, -1, zone, tlsConfig(ca, subjectDn));
        // Zone-scoped on purpose: the two-argument form would clear the secret in whichever zone
        // happens to be current rather than the one this client was created in.
        clientDetailsService.updateClientSecret(clientId, null, zone.getId());
    }

    /** Per RFC 8705 section 2.1.2 a client registers exactly one subject value to be bound to. */
    private static Map<String, Object> tlsConfig(X509Certificate ca, String expectedSubjectDn) throws Exception {
        return Map.of(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA, toPem(ca),
                TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CLAIM_MAPPINGS,
                List.of(new TlsClientAuthConfiguration.ClaimMapping("subject_cn", null, "app_id")),
                TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SUBJECT_DN, expectedSubjectDn);
    }

    /** @param zone the zone to address, or {@code null} for the default zone. */
    private MockHttpServletRequestBuilder mtlsPost(ZoneResolutionMode mode, IdentityZone zone,
                                                   String clientId, X509Certificate cert) {
        String subdomain = zone == null ? null : zone.getSubdomain();
        return withServletPath(mode.createRequestBuilder(subdomain, HttpMethod.POST, MTLS_PATH), mode,
                subdomain, MTLS_PATH)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_FORM_URLENCODED)
                .param("client_id", clientId)
                .param("grant_type", GRANT_TYPE_CLIENT_CREDENTIALS)
                .requestAttr("jakarta.servlet.request.X509Certificate", new X509Certificate[]{cert});
    }

    /**
     * MockMvc rejects a builder whose request URI does not decompose into contextPath +
     * servletPath, and in zone-path mode the URI still carries its {@code /z/{subdomain}} prefix
     * when the builder is constructed -- it is {@link ZonePathContextRewritingFilter} that splits
     * the two at request time, wrapping the request so that {@code getServletPath()} reports the
     * suffix alone. So the servlet path may only be pre-set when no such prefix is present, which
     * is every subdomain-addressed request plus any request aimed at the default zone.
     *
     * <p>This matters beyond mechanics: the mTLS filters key off {@code getServletPath()}, so a
     * request left with an empty servlet path would be refused for the wrong reason and a
     * negative test could pass without proving anything about zone isolation.
     */
    private static MockHttpServletRequestBuilder withServletPath(MockHttpServletRequestBuilder builder,
                                                                 ZoneResolutionMode mode,
                                                                 String subdomain, String path) {
        boolean zonePathPrefixPresent =
                mode == ZoneResolutionMode.ZONE_PATH && subdomain != null && !subdomain.isBlank();
        return zonePathPrefixPresent ? builder : builder.servletPath(mode.getServletPath(subdomain, path));
    }

    private MvcResult perform(MockHttpServletRequestBuilder builder) throws Exception {
        return mockMvc.perform(builder).andReturn();
    }

    private static String outcome(MvcResult result) throws Exception {
        String content = result.getResponse().getContentAsString();
        return "status=" + result.getResponse().getStatus() + ", body="
                + ((content == null || content.isBlank()) ? "<empty>" : content);
    }

    private static Map<String, Object> claimsOf(MvcResult result) throws Exception {
        Map<String, Object> body = JsonUtils.readValue(result.getResponse().getContentAsString(),
                new TypeReference<Map<String, Object>>() {});
        return JsonUtils.readValue(JwtHelper.decode((String) body.get("access_token")).getClaims(),
                new TypeReference<Map<String, Object>>() {});
    }

    private static X509Certificate leafSignedBy(X500Name caSubject, KeyPair caKeyPair, String subjectDn)
            throws Exception {
        return signCert(x500(subjectDn), caSubject, generateKeyPair().getPublic(),
                caKeyPair.getPrivate(), false);
    }

    /**
     * BouncyCastle encodes RDNs in the order given while RFC 4514 renders an encoded DN back to
     * front, so round-tripping through X500Principal keeps the certificate's subject reading as
     * written -- the form the client registers it in.
     */
    private static X500Name x500(String rfc2253Dn) {
        return X500Name.getInstance(new javax.security.auth.x500.X500Principal(rfc2253Dn).getEncoded());
    }

    private static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", BouncyCastleFipsProvider.PROVIDER_NAME);
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static X509Certificate signCert(X500Name subject, X500Name issuer, PublicKey subjectKey,
                                            PrivateKey issuerKey, boolean ca) throws Exception {
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuer, BigInteger.valueOf(System.nanoTime()),
                new Date(System.currentTimeMillis() - 120_000),
                new Date(System.currentTimeMillis() + 3_600_000L),
                subject, subjectKey);
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleFipsProvider.PROVIDER_NAME)
                .build(issuerKey);
        X509CertificateHolder holder = builder.build(signer);
        return new JcaX509CertificateConverter()
                .setProvider(BouncyCastleFipsProvider.PROVIDER_NAME)
                .getCertificate(holder);
    }

    private static String toPem(X509Certificate cert) throws Exception {
        StringWriter sw = new StringWriter();
        try (PemWriter pemWriter = new PemWriter(sw)) {
            pemWriter.writeObject(new PemObject("CERTIFICATE", cert.getEncoded()));
        }
        return sw.toString();
    }
}
