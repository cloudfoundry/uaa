package org.cloudfoundry.identity.uaa.mock.token;

import tools.jackson.core.type.TypeReference;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
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
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.oauth.tls.RawPeerCertificateCaptureFilter;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.ZoneContextPathSessionFilter;
import org.cloudfoundry.identity.uaa.zone.ZonePathContextRewritingFilter;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_CLIENT_CREDENTIALS;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_PASSWORD;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.config.BeanIds.SPRING_SECURITY_FILTER_CHAIN;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * Adversarial MockMvc coverage for the RFC 8705 mTLS token endpoint introduced by PR #3972.
 *
 * <p>Every refusal is asserted as a whole {@link Denial} -- HTTP status, OAuth error code and error
 * description together -- so that a test cannot go green on a 401 that happened for an unrelated
 * reason. That is not pedantry: an earlier version of B1 asserted only "not 200", passed on an
 * {@code invalid_scope} raised inside the grant, and hid the fact that certificate authentication had
 * already succeeded.
 *
 * <p>Tests whose display name begins with {@code FINDING} currently fail. They assert the security
 * property that ought to hold; the failure is the product not holding it, and the comment above each
 * assertion records the observed behaviour. They are not to be "fixed" by relaxing the assertion.
 *
 * <p>The MockMvc chain is rebuilt in {@link #setUpMtlsMockMvc()} to include
 * {@link RawPeerCertificateCaptureFilter}, which is registered in
 * {@code SpringServletXmlFiltersConfiguration} but is not added to the MockMvc chain by
 * {@code DefaultTestContext}. Requests set {@code jakarta.servlet.request.X509Certificate}
 * directly, which is the state the servlet container (or the buildpack
 * {@code ClientCertificateMapper}) leaves the request in before client authentication runs,
 * and they set {@code .servletPath("/oauth/mtls/token")} because MockMvc does not derive the
 * effective servlet path the way a real DispatcherServlet mapping would.
 */
@DefaultTestContext
@TestPropertySource(properties = {"uaa.mtls-enabled=true"})
class MtlsTokenEndpointHardeningMockMvcTests extends AbstractTokenMockMvcTests {

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

    @Qualifier("rawPeerCertificateCaptureFilter")
    @Autowired
    FilterRegistrationBean<RawPeerCertificateCaptureFilter> rawPeerCertificateCaptureFilterRegistration;

    private static KeyPair caKeyPair;
    private static X500Name caSubject;
    private static X509Certificate caCert;

    private static KeyPair rogueCaKeyPair;
    private static X500Name rogueCaSubject;
    private static X509Certificate rogueCaCert;

    @BeforeAll
    static void registerFipsProviderAndBuildCas() throws Exception {
        if (Security.getProvider(BouncyCastleFipsProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleFipsProvider());
        }
        caKeyPair = generateKeyPair();
        caSubject = new X500Name("CN=Test mTLS CA");
        caCert = signCert(caSubject, caSubject, caKeyPair.getPublic(), caKeyPair.getPrivate(),
                true, BigInteger.valueOf(1), 3_600_000L);

        rogueCaKeyPair = generateKeyPair();
        rogueCaSubject = new X500Name("CN=Rogue mTLS CA");
        rogueCaCert = signCert(rogueCaSubject, rogueCaSubject, rogueCaKeyPair.getPublic(),
                rogueCaKeyPair.getPrivate(), true, BigInteger.valueOf(1), 3_600_000L);
    }

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
    // Group A -- credential confusion between client_secret and tls_client_auth
    // ------------------------------------------------------------------------------------

    @Nested
    @DisplayName("A. client_secret vs tls_client_auth")
    class CredentialConfusion {

        @Test
        @DisplayName("A1. an mTLS-configured client cannot fall back to client_secret_basic at /oauth/token")
        void mtlsConfiguredClientCannotUseSecretAtPlainTokenEndpoint() throws Exception {
            // Client keeps its secret AND has tls-client-auth-ca configured.
            String clientId = mtlsClient("a1", GRANT_TYPE_CLIENT_CREDENTIALS, tlsConfig(caCert, "CN=a1-app"), true);

            MvcResult result = perform(post("/oauth/token")
                    .accept(APPLICATION_JSON)
                    .contentType(APPLICATION_FORM_URLENCODED)
                    .header("Authorization", basic(clientId, SECRET))
                    .param("grant_type", GRANT_TYPE_CLIENT_CREDENTIALS));

            assertThat(denial(result))
                    .as("opting a client into tls_client_auth must retire its secret as a live credential, "
                            + "and the denial must say so rather than looking like a wrong password")
                    .isEqualTo(new Denial(401, "invalid_client",
                            "tls_client_auth: configured clients must authenticate at "
                                    + "/oauth/mtls/token without client credentials"));
        }

        @Test
        @DisplayName("A2. an mTLS-configured client cannot present a cert AND a client_secret")
        void mtlsClientCannotCombineCertificateAndSecret() throws Exception {
            String clientId = mtlsClient("a2", GRANT_TYPE_CLIENT_CREDENTIALS, tlsConfig(caCert, "CN=a2-app"), true);
            X509Certificate leaf = leafSignedByCa("CN=a2-app");

            MvcResult result = perform(mtlsPost(clientId, GRANT_TYPE_CLIENT_CREDENTIALS, leaf)
                    .param("client_secret", SECRET));

            // Same denial as A1: presence of ANY credential short-circuits before the certificate is
            // even looked at. Pinning the message proves the request was refused for that reason and
            // not because the certificate happened to fail validation.
            assertThat(denial(result))
                    .as("a certificate and a secret must not be combinable on one request")
                    .isEqualTo(new Denial(401, "invalid_client",
                            "tls_client_auth: configured clients must authenticate at "
                                    + "/oauth/mtls/token without client credentials"));
        }

        @Test
        @DisplayName("A3. FINDING -- an ordinary secret client is served by the mTLS token endpoint")
        void ordinarySecretClientAtMtlsEndpoint() throws Exception {
            // No tls-client-auth-ca at all. Ordinary client_secret_basic. No certificate.
            String clientId = "mtlsprobea3" + generator.generate();
            setUpClients(clientId, "uaa.resource", "uaa.resource", GRANT_TYPE_CLIENT_CREDENTIALS,
                    false, null, null, -1, IdentityZone.getUaa(), Map.of());

            MvcResult result = perform(post(MTLS_PATH)
                    .accept(APPLICATION_JSON)
                    .contentType(APPLICATION_FORM_URLENCODED)
                    .servletPath(MTLS_PATH)
                    .header("Authorization", basic(clientId, SECRET))
                    .param("grant_type", GRANT_TYPE_CLIENT_CREDENTIALS));

            // The property does not prescribe WHICH fix: refusing the request and serving only
            // certificate-authenticated clients both satisfy it. FAILS TODAY because neither holds --
            // the request is served, and the token records no mTLS authentication.
            if (result.getResponse().getStatus() != 200) {
                assertThat(denial(result).error())
                        .as("if the endpoint refuses a non-mTLS client it must refuse cleanly")
                        .isEqualTo("invalid_client");
                return;
            }
            assertThat(claimsOf(result))
                    .as("/oauth/mtls/token is advertised as mtls_endpoint_aliases.token_endpoint, so any "
                            + "token it issues must have been authenticated by a client certificate")
                    .containsEntry("client_auth_method", "tls_client_auth");
        }

        @Test
        @DisplayName("A4. an mTLS client with no certificate on the request is rejected")
        void mtlsClientWithoutCertificateIsRejected() throws Exception {
            String clientId = mtlsClient("a4", GRANT_TYPE_CLIENT_CREDENTIALS, tlsConfig(caCert, "CN=a4-app"), false);

            MvcResult result = perform(post(MTLS_PATH)
                    .accept(APPLICATION_JSON)
                    .contentType(APPLICATION_FORM_URLENCODED)
                    .servletPath(MTLS_PATH)
                    .param("client_id", clientId)
                    .param("grant_type", GRANT_TYPE_CLIENT_CREDENTIALS));

            assertThat(denial(result))
                    .as("no certificate presented must fail closed")
                    .isEqualTo(new Denial(401, "invalid_client",
                            "tls_client_auth: certificate validation failed"));
        }
    }

    // ------------------------------------------------------------------------------------
    // Group B -- which grant types the mTLS endpoint will serve
    // ------------------------------------------------------------------------------------

    @Nested
    @DisplayName("B. grant types at the mTLS endpoint")
    class GrantTypes {

        @Test
        @DisplayName("B1. FINDING -- password grant at the mTLS endpoint mints a user token bound to the app's certificate")
        void passwordGrantAtMtlsEndpoint() throws Exception {
            String username = "mtlsuser" + generator.generate();
            ScimUser user = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager,
                    jdbcScimGroupProvisioning, username, "uaa.user", OriginKeys.UAA,
                    IdentityZone.getUaaZoneId());
            assertThat(user).isNotNull();

            // The client's scope must intersect the user's groups, otherwise the request dies with
            // invalid_scope inside the grant -- AFTER certificate authentication has already
            // succeeded -- which would tell us nothing about whether the grant is allowed here.
            String clientId = "mtlsb1" + generator.generate();
            setUpClients(clientId, "uaa.resource", "uaa.user",
                    "client_credentials,password,refresh_token",
                    false, null, null, -1, IdentityZone.getUaa(), tlsConfig(caCert, "CN=b1-app"));
            clientDetailsService.updateClientSecret(clientId, null);
            X509Certificate leaf = leafSignedByCa("CN=b1-app");

            MvcResult result = perform(mtlsPost(clientId, GRANT_TYPE_PASSWORD, leaf)
                    .param("username", username)
                    .param("password", SECRET)
                    .param("scope", "uaa.user")
                    .param("token_format", "jwt"));

            // Refusing the grant at this endpoint satisfies the property, and so does issuing a user
            // token that is not certificate-bound. FAILS TODAY because the token is both: cnf.x5t#S256
            // (RFC 8705 section 3 sender-constraint, "the presenter holds this certificate") sits
            // alongside user_id/user_name/email from the password grant and app_id from the
            // certificate. The returned refresh_token is also usable at this endpoint.
            if (result.getResponse().getStatus() != 200) {
                // Any clean client error is an acceptable refusal here -- invalid_grant for a grant
                // type the endpoint does not serve, invalid_client for a credential problem. What is
                // NOT acceptable is a 5xx or a body with no error code.
                assertThat(denial(result).status()).isBetween(400, 499);
                assertThat(denial(result).error())
                        .as("the refusal must carry an OAuth error code")
                        .isNotNull();
                return;
            }
            Map<String, Object> claims = claimsOf(result);
            assertThat(claims.containsKey("cnf") && claims.containsKey("user_id"))
                    .as("a token must not be both certificate-bound and a user token -- that conflates "
                            + "the app instance's identity with the user's. Actual claims: %s", claims)
                    .isFalse();
        }

        @Test
        @DisplayName("B2. client_credentials over tls_client_auth issues no refresh token")
        void clientCredentialsAtMtlsEndpointHasNoRefreshToken() throws Exception {
            String clientId = mtlsClient("b2", GRANT_TYPE_CLIENT_CREDENTIALS, tlsConfig(caCert, "CN=b2-app"), false);
            X509Certificate leaf = leafSignedByCa("CN=b2-app");

            MvcResult result = perform(mtlsPost(clientId, GRANT_TYPE_CLIENT_CREDENTIALS, leaf)
                    .param("token_format", "jwt"));

            assertThat(result.getResponse().getStatus()).isEqualTo(200);
            Map<String, Object> body = JsonUtils.readValue(
                    result.getResponse().getContentAsString(), new TypeReference<Map<String, Object>>() {});
            assertThat(body)
                    .as("ClientCredentialsTokenGranter strips the refresh token for tls_client_auth")
                    .doesNotContainKey("refresh_token");
            // Without this the test would pass even if the client had been authenticated some other way.
            assertThat(claimsOf(result))
                    .containsEntry("client_auth_method", "tls_client_auth")
                    .containsEntry("app_id", "b2-app");
        }
    }

    // ------------------------------------------------------------------------------------
    // Group C -- what a failed certificate validation actually returns
    // ------------------------------------------------------------------------------------

    @Nested
    @DisplayName("C. certificate validation failure semantics")
    class ValidationFailures {

        @Test
        @DisplayName("C1. a certificate signed by a DIFFERENT CA is rejected as an untrusted chain")
        void certificateFromWrongCaIsUnauthorized() throws Exception {
            String clientId = mtlsClient("c1", GRANT_TYPE_CLIENT_CREDENTIALS, tlsConfig(caCert, "CN=c1-attacker"), false);
            // Leaf chains to the rogue CA; the client trusts caCert.
            X509Certificate rogueLeaf = signCert(new X500Name("CN=c1-attacker"), rogueCaSubject,
                    generateKeyPair().getPublic(), rogueCaKeyPair.getPrivate(),
                    false, BigInteger.valueOf(99), 3_600_000L);

            assertThat(denial(perform(mtlsPost(clientId, GRANT_TYPE_CLIENT_CREDENTIALS, rogueLeaf))))
                    .as("the denial must name chain validation, so that it cannot be confused with any "
                            + "other reason a request might come back 401")
                    .isEqualTo(new Denial(401, "invalid_client",
                            "tls_client_auth: certificate chain validation failed: "
                                    + "Path does not chain with any of the trust anchors"));
        }

        @Test
        @DisplayName("C2. an EXPIRED certificate is rejected on the validity check")
        void expiredCertificateIsUnauthorized() throws Exception {
            String clientId = mtlsClient("c2", GRANT_TYPE_CLIENT_CREDENTIALS, tlsConfig(caCert, "CN=c2-app"), false);
            X509Certificate expiredLeaf = signCert(new X500Name("CN=c2-app"), caSubject,
                    generateKeyPair().getPublic(), caKeyPair.getPrivate(),
                    false, BigInteger.valueOf(98), -60_000L); // notAfter in the past

            // "validity check failed" is the JDK CertPathValidatorException text, so this assertion is
            // the one place here that could move under a JDK upgrade. It is pinned deliberately: the
            // point is to prove expiry -- not some other chain problem -- caused the rejection.
            assertThat(denial(perform(mtlsPost(clientId, GRANT_TYPE_CLIENT_CREDENTIALS, expiredLeaf))))
                    .as("an expired certificate must be rejected for being expired")
                    .isEqualTo(new Denial(401, "invalid_client",
                            "tls_client_auth: certificate chain validation failed: validity check failed"));
        }

        @Test
        @DisplayName("C3. a malformed tls-client-auth-ca is a configuration error, not a crash")
        void malformedCaPemIsUnauthorized() throws Exception {
            // setUpClients writes straight to the client store, bypassing ClientAdminEndpointsValidator --
            // which is what an already-persisted client from a BOSH oauth.clients bootstrap looks like,
            // so a malformed CA can reach the authentication path in production too.
            String clientId = mtlsClient("c3", GRANT_TYPE_CLIENT_CREDENTIALS,
                    Map.of(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA, "not-a-certificate",
                            TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SUBJECT_DN, "CN=c3-app"), false);
            X509Certificate leaf = leafSignedByCa("CN=c3-app");

            assertThat(denial(perform(mtlsPost(clientId, GRANT_TYPE_CLIENT_CREDENTIALS, leaf))))
                    .as("a broken CA in client config must be reported as a CA configuration error, "
                            + "distinctly from a certificate that simply did not validate")
                    .isEqualTo(new Denial(401, "invalid_client",
                            "tls_client_auth: CA configuration error: "
                                    + "No PEM object found in tls-client-auth-ca"));
        }

        @Test
        @DisplayName("C4. a CA certificate presented as the client leaf is rejected by the end-entity check")
        void caCertificatePresentedAsLeafIsRejected() throws Exception {
            String clientId = mtlsClient("c4", GRANT_TYPE_CLIENT_CREDENTIALS, tlsConfig(caCert, "CN=Test mTLS CA"), false);

            // The trust anchor itself, presented as the end-entity certificate. Pinning the message is
            // what makes this test meaningful: chain validation ALSO rejects it, so a bare 401
            // assertion would pass even if validateEndEntityConstraints were deleted.
            assertThat(denial(perform(mtlsPost(clientId, GRANT_TYPE_CLIENT_CREDENTIALS, caCert))))
                    .as("validateEndEntityConstraints must be the thing that rejects a CA=true leaf")
                    .isEqualTo(new Denial(401, "invalid_client",
                            "tls_client_auth: certificate chain validation failed: "
                                    + "presented end-entity certificate is itself a CA certificate"));
        }

        @Test
        @DisplayName("C5. FINDING -- the same wrong-CA failure returns 500 when reached via Basic auth")
        void wrongCaViaBasicAuthWithEmptySecret() throws Exception {
            String clientId = mtlsClient("c5", GRANT_TYPE_CLIENT_CREDENTIALS, tlsConfig(caCert, "CN=c5-attacker"), false);
            X509Certificate rogueLeaf = signCert(new X500Name("CN=c5-attacker"), rogueCaSubject,
                    generateKeyPair().getPublic(), rogueCaKeyPair.getPrivate(),
                    false, BigInteger.valueOf(97), 3_600_000L);

            // Deliberately NO client_id parameter. ClientParametersAuthenticationFilter
            // .wrapClientCredentialLogin skips entirely when an Authorization header is present, so
            // this is handled by ClientBasicAuthenticationFilter instead. An empty secret still
            // satisfies ObjectUtils.isEmpty(credentials) in ClientDetailsAuthenticationProvider, so
            // certificate validation IS reached -- but via a filter with a narrower catch.
            MvcResult result = perform(post(MTLS_PATH)
                    .accept(APPLICATION_JSON)
                    .contentType(APPLICATION_FORM_URLENCODED)
                    .servletPath(MTLS_PATH)
                    .header("Authorization", basic(clientId, ""))
                    .param("grant_type", GRANT_TYPE_CLIENT_CREDENTIALS)
                    .requestAttr("jakarta.servlet.request.X509Certificate",
                            new X509Certificate[]{rogueLeaf}));

            // FAILS TODAY (500, empty body, plus an ERROR "Uncaught Exception:" stack trace in the log).
            // C1-C4 return a clean 401 only because
            // AbstractClientParametersAuthenticationFilter.performClientAuthentication wraps EVERY
            // exception in BadCredentialsException. ClientBasicAuthenticationFilter catches only
            // AuthenticationException, and InvalidClientDetailsException is a UaaException ->
            // OAuth2Exception -> RuntimeException, so here it escapes the security chain.
            assertThat(denial(result))
                    .as("the same certificate and the same client must be denied identically however "
                            + "the client_id reached UAA. Actual: %s", outcome(result))
                    .isEqualTo(new Denial(401, "invalid_client",
                            "tls_client_auth: certificate chain validation failed: "
                                    + "Path does not chain with any of the trust anchors"));
        }
    }

    // ------------------------------------------------------------------------------------
    // Group D -- how far certificate-derived claim mappings can reach into the token
    // ------------------------------------------------------------------------------------

    @Nested
    @DisplayName("D. claim mapping reach")
    class ClaimMapping {

        @Test
        @DisplayName("D1. claim mappings cannot overwrite UAA-owned protected claims")
        void claimMappingsCannotOverwriteProtectedClaims() throws Exception {
            Map<String, Object> config = Map.of(
                    TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA, toPem(caCert),
                    TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CLAIM_MAPPINGS, List.of(
                            new TlsClientAuthConfiguration.ClaimMapping("subject_cn", null, "scope"),
                            new TlsClientAuthConfiguration.ClaimMapping("subject_ou", "esc:(.+)", "client_id"),
                            new TlsClientAuthConfiguration.ClaimMapping("subject_o", null, "zid")),
                    TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SUBJECT_DN,
                    "CN=uaa.admin,OU=esc:admin-client,O=some-other-zone");
            String clientId = mtlsClient("d1", GRANT_TYPE_CLIENT_CREDENTIALS, config, false);
            X509Certificate leaf = leafSignedByCa("CN=uaa.admin,OU=esc:admin-client,O=some-other-zone");

            MvcResult result = perform(mtlsPost(clientId, GRANT_TYPE_CLIENT_CREDENTIALS, leaf)
                    .param("token_format", "jwt"));
            assertThat(result.getResponse().getStatus()).isEqualTo(200);

            Map<String, Object> claims = claimsOf(result);
            // The certificate really was the credential, and the mappings really were applied --
            // otherwise the assertions below would be vacuous.
            assertThat(claims).containsEntry("client_auth_method", "tls_client_auth");
            // UaaTokenServices.NON_ADDITIONAL_ROOT_CLAIMS is the control that makes this safe.
            assertThat(claims.get("client_id"))
                    .as("a certificate must not be able to rename the client")
                    .isEqualTo(clientId);
            assertThat((List<String>) claims.get("scope"))
                    .as("a certificate must not be able to grant itself scopes")
                    .containsExactly("uaa.resource");
            assertThat(claims.get("zid"))
                    .as("a certificate must not be able to move the token to another zone")
                    .isEqualTo(IdentityZone.getUaaZoneId());
        }

        @Test
        @DisplayName("D2. FINDING -- a sub template with no placeholders forges an arbitrary subject")
        void subTemplateWithoutPlaceholdersForgesSubject() throws Exception {
            String clientId = "mtlsd2" + generator.generate();
            // Created through the client-admin API, not written straight to the store, so that a fix
            // applied in ClientAdminEndpointsValidator is visible here.
            MvcResult created = createClientViaAdminApi(clientId, Map.of(
                    TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA, toPem(caCert),
                    TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CLAIM_MAPPINGS, List.of(
                            new TlsClientAuthConfiguration.ClaimMapping("subject_cn", null, "app_id")),
                    // No {placeholder} at all -- MtlsClaimsEnhancer.renderTemplate returns it verbatim
                    // and UaaTokenServices re-applies sub AFTER its own defaults.
                    TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SUB_TEMPLATE,
                    "00000000-0000-0000-0000-000000000000",
                    TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SUBJECT_DN, "CN=d2-app"));

            if (created.getResponse().getStatus() != 201) {
                assertThat(denial(created).description())
                        .as("rejecting the configuration is a valid fix, but it must be rejected FOR "
                                + "THIS REASON and not for some unrelated validation failure")
                        .contains(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SUB_TEMPLATE);
                return;
            }

            MvcResult result = perform(mtlsPost(clientId, GRANT_TYPE_CLIENT_CREDENTIALS,
                    leafSignedByCa("CN=d2-app")).param("token_format", "jwt"));
            assertThat(result.getResponse().getStatus()).isEqualTo(200);

            // FAILS TODAY. ClientAdminEndpointsValidator.validateTemplatePlaceholders only checks that
            // placeholders that ARE present are declared; it never requires one. So a constant template
            // makes sub any fixed string a client admin chooses -- e.g. a real user's UUID.
            assertThat(claimsOf(result).get("sub"))
                    .as("sub must stay derived from the authenticated client or its certificate")
                    .isEqualTo(clientId);
        }

        @Test
        @DisplayName("D3. FINDING -- a claim mapping can forge authentication-context claims (amr/acr)")
        void claimMappingCanForgeAuthenticationContextClaims() throws Exception {
            String clientId = "mtlsd3" + generator.generate();
            MvcResult created = createClientViaAdminApi(clientId, Map.of(
                    TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA, toPem(caCert),
                    TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CLAIM_MAPPINGS, List.of(
                            new TlsClientAuthConfiguration.ClaimMapping("subject_cn", null, "amr"),
                            new TlsClientAuthConfiguration.ClaimMapping("subject_o", null, "acr")),
                    TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SUBJECT_DN,
                    "CN=mfa,O=urn:example:high"));

            if (created.getResponse().getStatus() != 201) {
                assertThat(denial(created).description())
                        .as("rejecting a mapping onto a reserved claim name is a valid fix, but it must "
                                + "be rejected for that reason")
                        .contains(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CLAIM_MAPPINGS);
                return;
            }

            MvcResult result = perform(mtlsPost(clientId, GRANT_TYPE_CLIENT_CREDENTIALS,
                    leafSignedByCa("CN=mfa,O=urn:example:high")).param("token_format", "jwt"));
            assertThat(result.getResponse().getStatus()).isEqualTo(200);

            // FAILS TODAY. NON_ADDITIONAL_ROOT_CLAIMS protects UAA's own claims but not the
            // authentication-context claims downstream policy engines read, and
            // ClientAdminEndpointsValidator applies no allowlist to claim NAMES.
            assertThat(claimsOf(result))
                    .as("a certificate subject field must not be able to assert how the caller authenticated")
                    .doesNotContainKeys("amr", "acr");
        }

        @Test
        @DisplayName("D4. required-claims gates authentication for a certificate from the same CA")
        void requiredClaimsGateAuthentication() throws Exception {
            Map<String, Object> config = Map.of(
                    TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA, toPem(caCert),
                    TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CLAIM_MAPPINGS, List.of(
                            new TlsClientAuthConfiguration.ClaimMapping("subject_ou", "space:(.+)", "space_guid")),
                    TlsClientAuthConfiguration.TLS_CLIENT_AUTH_REQUIRED_CLAIMS,
                    Map.of("space_guid", "the-only-allowed-space"));
            String clientId = mtlsClient("d4", GRANT_TYPE_CLIENT_CREDENTIALS, config, false);

            // Same CA, wrong space -- the shared-CA scenario the docs call out.
            X509Certificate wrongSpace = leafSignedByCa("CN=d4-app,OU=space:some-other-space");
            // NOTE: this is the same message A4 gets for presenting no certificate at all. The product
            // does not distinguish "your certificate is not trusted" from "your certificate is trusted
            // but not permitted here", so this assertion pins the denial that exists rather than the
            // denial that would be accurate. The right-space case below is what proves the gate ran.
            assertThat(denial(perform(mtlsPost(clientId, GRANT_TYPE_CLIENT_CREDENTIALS, wrongSpace))))
                    .as("a valid certificate from the same CA but the wrong space must not authenticate")
                    .isEqualTo(new Denial(401, "invalid_client",
                            "tls_client_auth: certificate validation failed"));

            X509Certificate rightSpace = leafSignedByCa("CN=d4-app,OU=space:the-only-allowed-space");
            MvcResult allowed = perform(mtlsPost(clientId, GRANT_TYPE_CLIENT_CREDENTIALS, rightSpace)
                    .param("token_format", "jwt"));
            assertThat(allowed.getResponse().getStatus())
                    .as("the permitted space must still authenticate, otherwise the rejection above "
                            + "proves nothing about required-claims")
                    .isEqualTo(200);
            assertThat(claimsOf(allowed))
                    .containsEntry("space_guid", "the-only-allowed-space")
                    .containsEntry("client_auth_method", "tls_client_auth");
        }
    }

    // ------------------------------------------------------------------------------------
    // Group E -- what a certificate actually proves about WHICH client is calling
    // ------------------------------------------------------------------------------------

    @Nested
    @DisplayName("E. certificate-to-client binding")
    class CertificateClientBinding {

        /**
         * A CA-only client: no RFC 8705 section 2.1.2 subject parameter at all. Chain validation
         * would prove only that the CA issued the certificate, so nothing distinguishes this
         * client from any other the CA ever issued.
         */
        private static Map<String, Object> caOnlyConfigWithNoBinding() throws Exception {
            return Map.of(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA, toPem(caCert),
                    TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CLAIM_MAPPINGS,
                    List.of(new TlsClientAuthConfiguration.ClaimMapping("subject_cn", null, "app_id")));
        }

        @Test
        @DisplayName("E2. a client with no subject binding is refused rather than trusting the CA alone")
        void caOnlyClientWithNoSubjectBindingIsRefused() throws Exception {
            String clientId = mtlsClient("e2", GRANT_TYPE_CLIENT_CREDENTIALS, caOnlyConfigWithNoBinding(), false);
            X509Certificate ownCert = leafSignedByCa("CN=e2-app");

            MvcResult result = perform(mtlsPost(clientId, GRANT_TYPE_CLIENT_CREDENTIALS, ownCert));

            assertThat(denial(result).status())
                    .as("a client that binds nothing but the CA must fail closed. Actual: %s", outcome(result))
                    .isEqualTo(401);
            assertThat(denial(result).description())
                    .as("the refusal must name the configuration the operator has to supply")
                    .contains(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SUBJECT_DN);
        }

        @Test
        @DisplayName("E1. one client's certificate cannot authenticate as a different client sharing the same CA")
        void certificateOfOneClientCannotAuthenticateAsAnotherClientSharingTheCa() throws Exception {
            // Two SEPARATE registered clients trusting the same CA. Not contrived: the documented
            // use case is the Cloud Foundry Diego instance-identity CA, which issues a certificate
            // to every app instance in the foundation, so every mTLS client in that foundation
            // shares one anchor. RFC 8705 section 2.1 makes the subject -- not the issuer -- the
            // thing that identifies the client.
            String victimClientId = mtlsClient("e1victim", GRANT_TYPE_CLIENT_CREDENTIALS,
                    tlsConfig(caCert, "CN=e1-victim-app"), false);

            // The attacker legitimately holds a certificate for its OWN workload, issued by the very
            // same shared CA. It was never issued for, and says nothing about, the victim client.
            X509Certificate attackerOwnCert = leafSignedByCa("CN=e1-attacker-app");

            MvcResult result = perform(mtlsPost(victimClientId, GRANT_TYPE_CLIENT_CREDENTIALS, attackerOwnCert)
                    .param("token_format", "jwt"));

            assertThat(denial(result).status())
                    .as("a certificate issued for one workload must not authenticate as a different "
                            + "registered client that merely shares the same CA. Actual: %s", outcome(result))
                    .isEqualTo(401);

            // Positive control: the victim's own certificate still works, so the rejection above
            // proves subject binding rather than the client being broken outright.
            X509Certificate victimOwnCert = leafSignedByCa("CN=e1-victim-app");
            MvcResult allowed = perform(mtlsPost(victimClientId, GRANT_TYPE_CLIENT_CREDENTIALS, victimOwnCert)
                    .param("token_format", "jwt"));
            assertThat(allowed.getResponse().getStatus())
                    .as("Actual: %s", outcome(allowed))
                    .isEqualTo(200);
            assertThat(claimsOf(allowed))
                    .containsEntry("app_id", "e1-victim-app")
                    .containsEntry("client_auth_method", "tls_client_auth");
        }

        @Test
        @DisplayName("E3. a SAN-bound client authenticates on its SAN, not its subject DN")
        void sanBoundClientAuthenticatesOnItsSan() throws Exception {
            Map<String, Object> config = Map.of(
                    TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA, toPem(caCert),
                    TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SAN_DNS, "e3-app.example.com");
            String clientId = mtlsClient("e3", GRANT_TYPE_CLIENT_CREDENTIALS, config, false);

            MvcResult allowed = perform(mtlsPost(clientId, GRANT_TYPE_CLIENT_CREDENTIALS,
                    leafWithDnsSan("CN=anything-at-all", "e3-app.example.com")));
            assertThat(allowed.getResponse().getStatus())
                    .as("Actual: %s", outcome(allowed))
                    .isEqualTo(200);

            MvcResult refused = perform(mtlsPost(clientId, GRANT_TYPE_CLIENT_CREDENTIALS,
                    leafWithDnsSan("CN=anything-at-all", "other.example.com")));
            assertThat(denial(refused).status())
                    .as("a different dNSName is a different client. Actual: %s", outcome(refused))
                    .isEqualTo(401);
        }
    }

    // ------------------------------------------------------------------------------------
    // helpers
    // ------------------------------------------------------------------------------------

    private String mtlsClient(String tag, String grantTypes, Map<String, Object> tlsConfig, boolean keepSecret) {
        String clientId = "mtls" + tag + generator.generate();
        setUpClients(clientId, "uaa.resource", "uaa.resource", grantTypes,
                false, null, null, -1, IdentityZone.getUaa(), tlsConfig);
        if (!keepSecret) {
            clientDetailsService.updateClientSecret(clientId, null);
        }
        return clientId;
    }

    /**
     * A client bound to {@code expectedSubjectDn} per RFC 8705 section 2.1.2. Every mTLS client
     * must register exactly one subject value, so tests exercising other properties (grant types,
     * chain-validation semantics, claim mapping) still have to declare the subject of the
     * certificate they intend to present.
     */
    private static Map<String, Object> tlsConfig(X509Certificate ca, String expectedSubjectDn) throws Exception {
        return Map.of(TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CA, toPem(ca),
                TlsClientAuthConfiguration.TLS_CLIENT_AUTH_CLAIM_MAPPINGS,
                List.of(new TlsClientAuthConfiguration.ClaimMapping("subject_cn", null, "app_id")),
                TlsClientAuthConfiguration.TLS_CLIENT_AUTH_SUBJECT_DN, expectedSubjectDn);
    }

    private MockHttpServletRequestBuilder mtlsPost(String clientId, String grantType, X509Certificate cert) {
        return post(MTLS_PATH)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_FORM_URLENCODED)
                .servletPath(MTLS_PATH)
                .param("client_id", clientId)
                .param("grant_type", grantType)
                .requestAttr("jakarta.servlet.request.X509Certificate", new X509Certificate[]{cert});
    }

    /**
     * Creates a client through the client-admin API rather than writing straight to the client store,
     * so that validation added in {@code ClientAdminEndpointsValidator} is exercised. The client has
     * no secret: {@code tls-client-auth-ca} is its only credential.
     */
    private MvcResult createClientViaAdminApi(String clientId, Map<String, Object> tlsProperties)
            throws Exception {
        Map<String, Object> client = new HashMap<>(tlsProperties);
        client.put("client_id", clientId);
        client.put("authorized_grant_types", List.of(GRANT_TYPE_CLIENT_CREDENTIALS));
        client.put("scope", List.of("uaa.none"));
        client.put("authorities", List.of("uaa.resource"));
        return perform(post("/oauth/clients")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(client)));
    }

    private MvcResult perform(MockHttpServletRequestBuilder builder) throws Exception {
        return mockMvc.perform(builder).andReturn();
    }

    /**
     * The full shape of a refusal: HTTP status plus the OAuth error code and description. Asserted as
     * one value so a test cannot go green on a refusal that happened for an unrelated reason.
     * {@code error}/{@code description} are null when the response body is not an OAuth error object
     * (e.g. an empty 500 body), which is itself a meaningful thing to assert against.
     */
    record Denial(int status, String error, String description) {}

    static Denial denial(MvcResult result) throws Exception {
        String content = result.getResponse().getContentAsString();
        String error = null;
        String description = null;
        if (content != null && content.startsWith("{")) {
            Map<String, Object> body = JsonUtils.readValue(
                    content, new TypeReference<Map<String, Object>>() {});
            error = (String) body.get("error");
            description = (String) body.get("error_description");
        }
        return new Denial(result.getResponse().getStatus(), error, description);
    }

    /** Human-readable outcome for assertion messages: decoded token claims when one was issued. */
    static String outcome(MvcResult result) throws Exception {
        String content = result.getResponse().getContentAsString();
        String detail = (content == null || content.isBlank()) ? "<empty body>" : content;
        if (content != null && content.contains("\"access_token\"")) {
            detail = "token issued with claims " + claimsOf(result);
        }
        return "status=" + result.getResponse().getStatus() + ", " + detail;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> claimsOf(MvcResult result) throws Exception {
        Map<String, Object> body = JsonUtils.readValue(
                result.getResponse().getContentAsString(), new TypeReference<Map<String, Object>>() {});
        return JsonUtils.readValue(
                JwtHelper.decode((String) body.get("access_token")).getClaims(), Map.class);
    }

    private static String basic(String clientId, String secret) {
        return "Basic " + Base64.getEncoder().encodeToString(
                (clientId + ":" + secret).getBytes(StandardCharsets.UTF_8));
    }

    private static X509Certificate leafSignedByCa(String subjectDn) throws Exception {
        return signCert(new X500Name(subjectDn), caSubject, generateKeyPair().getPublic(),
                caKeyPair.getPrivate(), false, BigInteger.valueOf(System.nanoTime()), 3_600_000L);
    }

    /** A CA-issued leaf carrying a dNSName subjectAltName, for RFC 8705 SAN-bound clients. */
    private static X509Certificate leafWithDnsSan(String subjectDn, String dnsName) throws Exception {
        X500Name subject = new X500Name(subjectDn);
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                caSubject, BigInteger.valueOf(System.nanoTime()),
                new Date(System.currentTimeMillis() - 120_000),
                new Date(System.currentTimeMillis() + 3_600_000L),
                subject, generateKeyPair().getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        builder.addExtension(Extension.subjectAlternativeName, false,
                new GeneralNames(new GeneralName(GeneralName.dNSName, dnsName)));
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleFipsProvider.PROVIDER_NAME)
                .build(caKeyPair.getPrivate());
        return new JcaX509CertificateConverter()
                .setProvider(BouncyCastleFipsProvider.PROVIDER_NAME)
                .getCertificate(builder.build(signer));
    }

    private static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", BouncyCastleFipsProvider.PROVIDER_NAME);
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    private static X509Certificate signCert(X500Name subject, X500Name issuer, PublicKey subjectKey,
            PrivateKey signerKey, boolean isCa, BigInteger serial, long validForMillis) throws Exception {
        Date notBefore = new Date(System.currentTimeMillis() - 120_000);
        Date notAfter = new Date(System.currentTimeMillis() + validForMillis);
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuer, serial, notBefore, notAfter, subject, subjectKey);
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(isCa));
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleFipsProvider.PROVIDER_NAME)
                .build(signerKey);
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
