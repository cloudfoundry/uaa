package org.cloudfoundry.identity.uaa.mock.token;

import tools.jackson.core.type.TypeReference;
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
import org.cloudfoundry.identity.uaa.oauth.tls.MtlsEndpointAvailabilityFilter;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.ZoneContextPathSessionFilter;
import org.cloudfoundry.identity.uaa.zone.ZonePathContextRewritingFilter;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_CLIENT_CREDENTIALS;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.security.config.BeanIds.SPRING_SECURITY_FILTER_CHAIN;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * The other half of {@link MtlsTokenEndpointHardeningMockMvcTests}: what the mTLS feature looks like
 * on a deployment that has NOT enabled it ({@code uaa.mtls-enabled} absent/false, which is the default
 * for every existing UAA).
 *
 * <p>This matters because PR #3972 gates the feature asymmetrically. The security filter chain
 * ({@code mtlsTokenEndpointSecurity}) is {@code @ConditionalOnProperty("uaa.mtls-enabled")}, but
 * {@code UaaTokenEndpoint}'s {@code @RequestMapping} now lists {@code /oauth/mtls/token}
 * unconditionally, and both new servlet filters are registered unconditionally in
 * {@code SpringServletXmlFiltersConfiguration}. So with the feature off, the path still resolves to a
 * controller -- it just falls through to whichever chain matches next.
 */
@DefaultTestContext
@TestPropertySource(properties = {"uaa.mtls-enabled=false"})
class MtlsDisabledTokenEndpointMockMvcTests extends AbstractTokenMockMvcTests {

    private static final String MTLS_PATH = "/oauth/mtls/token";

    @Qualifier(SPRING_SECURITY_FILTER_CHAIN)
    @Autowired
    FilterChainProxy securityFilterChain;

    @Qualifier(ZonePathContextRewritingFilter.REGISTRATION_BEAN_NAME)
    @Autowired
    FilterRegistrationBean<ZonePathContextRewritingFilter> zonePathFilterRegistration;

    @Qualifier(ZoneContextPathSessionFilter.REGISTRATION_BEAN_NAME)
    @Autowired
    FilterRegistrationBean<ZoneContextPathSessionFilter> zoneContextPathSessionFilterRegistration;

    /**
     * Registered in {@code SpringServletXmlFiltersConfiguration} but not added to the MockMvc chain by
     * {@code DefaultTestContext}, so it has to be wired in explicitly -- exactly as it runs in the
     * real servlet container, before Spring Security.
     */
    @Qualifier("mtlsEndpointAvailabilityFilter")
    @Autowired
    FilterRegistrationBean<MtlsEndpointAvailabilityFilter> mtlsEndpointAvailabilityFilterRegistration;

    @BeforeEach
    void setUpMockMvcWithAvailabilityFilter() {
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
                .addFilter(zonePathFilterRegistration.getFilter())
                .addFilter(zoneContextPathSessionFilterRegistration.getFilter())
                .addFilter(mtlsEndpointAvailabilityFilterRegistration.getFilter())
                .addFilter(securityFilterChain)
                .build();
        testClient = new TestClient(mockMvc);
    }

    @BeforeAll
    static void registerFipsProvider() {
        if (Security.getProvider(BouncyCastleFipsProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleFipsProvider());
        }
    }

    @Test
    @DisplayName("E1. PROBE -- with mTLS disabled, /oauth/mtls/token should not be a live endpoint")
    void mtlsTokenEndpointIsNotServedWhenDisabled() throws Exception {
        String clientId = "mtlsoffe1" + generator.generate();
        setUpClients(clientId, "uaa.resource", "uaa.resource", GRANT_TYPE_CLIENT_CREDENTIALS,
                false, null, null, -1, IdentityZone.getUaa(), Map.of());

        MvcResult result = mockMvc.perform(post(MTLS_PATH)
                        .accept(APPLICATION_JSON)
                        .contentType(APPLICATION_FORM_URLENCODED)
                        .servletPath(MTLS_PATH)
                        .header("Authorization", basic(clientId, SECRET))
                        .param("grant_type", GRANT_TYPE_CLIENT_CREDENTIALS))
                .andReturn();

        // FAILS TODAY (403, "Could not verify the provided CSRF token because no token was found to
        // compare."). That 403 is the uiSecurity catch-all's CsrfFilter answering, which proves the
        // request reaches the browser login chain rather than not resolving: mtlsTokenEndpointSecurity
        // is @ConditionalOnProperty, but UaaTokenEndpoint's @RequestMapping lists /oauth/mtls/token
        // unconditionally. It fails closed here, but by accident rather than by gate.
        assertThat(result.getResponse().getStatus())
                .as("a disabled feature's endpoint must not resolve at all. Actual: %s",
                        MtlsTokenEndpointHardeningMockMvcTests.outcome(result))
                .isEqualTo(404);
    }

    @Test
    @DisplayName("E2. the client admin API refuses tls-client-auth-ca when mTLS is disabled")
    void clientAdminApiRejectsTlsConfigWhenDisabled() throws Exception {
        String clientId = "mtlsoffe2" + generator.generate();
        Map<String, Object> client = Map.of(
                "client_id", clientId,
                "client_secret", SECRET,
                "authorized_grant_types", List.of(GRANT_TYPE_CLIENT_CREDENTIALS),
                "scope", List.of("uaa.none"),
                "authorities", List.of("uaa.resource"),
                TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA, selfSignedCaPem());

        MvcResult result = mockMvc.perform(post("/oauth/clients")
                        .header("Authorization", "Bearer " + adminToken)
                        .accept(APPLICATION_JSON)
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(client)))
                .andReturn();

        assertThat(MtlsTokenEndpointHardeningMockMvcTests.denial(result))
                .as("the refusal must name the platform flag, so an operator knows what to turn on "
                        + "rather than thinking the CA itself was rejected")
                .isEqualTo(new MtlsTokenEndpointHardeningMockMvcTests.Denial(400, "invalid_client",
                        "tls-client-auth-ca / tls-client-auth-trusted-proxy-ca require uaa.mtls-enabled "
                                + "to be true on this UAA deployment. ClientID: " + clientId));
    }

    @Test
    @DisplayName("E3. OIDC discovery does not advertise tls_client_auth or mtls_endpoint_aliases when disabled")
    void discoveryDoesNotAdvertiseMtlsWhenDisabled() throws Exception {
        MvcResult result = mockMvc.perform(get("/.well-known/openid-configuration")
                        .accept(APPLICATION_JSON))
                .andReturn();

        assertThat(result.getResponse().getStatus()).isEqualTo(200);
        Map<String, Object> discovery = JsonUtils.readValue(
                result.getResponse().getContentAsString(), new TypeReference<Map<String, Object>>() {});

        assertThat((List<String>) discovery.get("token_endpoint_auth_methods_supported"))
                .as("a disabled feature must not be advertised, and the rest of the advertised set "
                        + "must be unchanged by this PR")
                .containsExactly("client_secret_basic", "client_secret_post", "private_key_jwt");
        assertThat(discovery)
                .as("mtls_endpoint_aliases is only meaningful when the endpoint exists")
                .doesNotContainKey("mtls_endpoint_aliases");
    }

    @Test
    @DisplayName("E4. an existing client carrying token-endpoint-auth-method can still be updated")
    void clientCarryingTokenEndpointAuthMethodKeyIsNotBricked() throws Exception {
        // ClientAdminEndpointsValidator now throws on the mere PRESENCE of this key in
        // additionalInformation, for EVERY client create/update -- mTLS or not. The key is not a
        // UAA property (UAA's is token_endpoint_auth_methods_supported, discovery metadata), but
        // hyphenated unknown keys from a BOSH oauth.clients manifest land in additionalInformation,
        // so a deployment may already have clients carrying it.
        String clientId = "mtlsoffe4" + generator.generate();
        Map<String, Object> client = Map.of(
                "client_id", clientId,
                "client_secret", SECRET,
                "authorized_grant_types", List.of(GRANT_TYPE_CLIENT_CREDENTIALS),
                "scope", List.of("uaa.none"),
                "authorities", List.of("uaa.resource"),
                "token-endpoint-auth-method", "client_secret_basic");

        MvcResult result = mockMvc.perform(post("/oauth/clients")
                        .header("Authorization", "Bearer " + adminToken)
                        .accept(APPLICATION_JSON)
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(client)))
                .andReturn();

        // FAILS TODAY (400, "token-endpoint-auth-method is not supported; configure tls-client-auth-ca
        // to enable mTLS for client_id=..."). That is a new, unconditional rejection of a key this PR
        // did not introduce and does not use, applied to every client create/update. Any deployment
        // already setting it -- silently ignored before -- can no longer create or update those clients.
        assertThat(result.getResponse().getStatus())
                .as("an unrelated additionalInformation key must not block client creation. Actual: %s",
                        MtlsTokenEndpointHardeningMockMvcTests.outcome(result))
                .isEqualTo(201);
    }

    private static String basic(String clientId, String secret) {
        return "Basic " + Base64.getEncoder().encodeToString(
                (clientId + ":" + secret).getBytes(StandardCharsets.UTF_8));
    }

    private static String selfSignedCaPem() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", BouncyCastleFipsProvider.PROVIDER_NAME);
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        X500Name subject = new X500Name("CN=Disabled Feature CA");
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                subject, BigInteger.ONE,
                new Date(System.currentTimeMillis() - 60_000),
                new Date(System.currentTimeMillis() + 3_600_000),
                subject, kp.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleFipsProvider.PROVIDER_NAME)
                .build(kp.getPrivate());
        X509CertificateHolder holder = builder.build(signer);
        X509Certificate cert = new JcaX509CertificateConverter()
                .setProvider(BouncyCastleFipsProvider.PROVIDER_NAME)
                .getCertificate(holder);
        StringWriter sw = new StringWriter();
        try (PemWriter pemWriter = new PemWriter(sw)) {
            pemWriter.writeObject(new PemObject("CERTIFICATE", cert.getEncoded()));
        }
        return sw.toString();
    }
}
