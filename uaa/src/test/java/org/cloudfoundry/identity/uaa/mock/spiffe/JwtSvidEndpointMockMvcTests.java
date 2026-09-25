package org.cloudfoundry.identity.uaa.mock.spiffe;

import tools.jackson.core.type.TypeReference;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.cloudfoundry.identity.uaa.mock.token.AbstractTokenMockMvcTests;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.spiffe.SpiffeTestCerts;
import org.cloudfoundry.identity.uaa.spiffe.SpiffeTestCerts.CertKey;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.env.MapPropertySource;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.Signature;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * End-to-end coverage of {@code POST /jwt-svid/sign} (RFC UAA-SPIFFE-001) through the real
 * filter chain, with real BouncyCastle-FIPS certificates and real proof-of-possession
 * signatures.
 *
 * <p>The whole feature is gated behind {@code @ConditionalOnProperty("uaa.spiffe.instance-identity-ca")},
 * so {@link SpiffeEnabled} injects a runtime-generated CA into the environment before the
 * context refreshes. Declaring it via {@code @ContextConfiguration} also changes the context
 * cache key, so these tests get their own context rather than poisoning the shared one.
 */
@ContextConfiguration(initializers = JwtSvidEndpointMockMvcTests.SpiffeEnabled.class)
class JwtSvidEndpointMockMvcTests extends AbstractTokenMockMvcTests {

    private static final String TRUST_DOMAIN = "cf.example.com";
    private static final String SIGN_PATH = "/jwt-svid/sign";
    private static final String AUDIENCE = "https://iam.example.com/projects/1/workloadIdentityPools/cf";

    /** The CA whose PEM is fed to {@code uaa.spiffe.instance-identity-ca}, and the key to forge against. */
    private static final CertKey CA = SpiffeTestCerts.newCa();

    /**
     * Applied before refresh, so {@code @ConditionalOnProperty} sees the property when bean
     * definitions are evaluated. Kebab-case is used deliberately: it is the only spelling that
     * satisfies both {@code @ConditionalOnProperty} (exact key lookup, no relaxed binding) and
     * {@code @ConfigurationProperties} (relaxed binding).
     */
    static class SpiffeEnabled implements ApplicationContextInitializer<ConfigurableApplicationContext> {
        @Override
        public void initialize(ConfigurableApplicationContext applicationContext) {
            Map<String, Object> properties = new HashMap<>();
            properties.put("uaa.spiffe.instance-identity-ca", SpiffeTestCerts.certificatePem(CA.certificate()));
            properties.put("uaa.spiffe.trust-domain", TRUST_DOMAIN);
            applicationContext.getEnvironment().getPropertySources()
                    .addFirst(new MapPropertySource("spiffeTestProperties", properties));
        }
    }

    /** The caller identity for the endpoint: the "SPIFFE Agent" client, bearing {@code uaa.resource}. */
    private String clientId;

    @BeforeEach
    void createCallingClient() {
        clientId = "spiffeagent" + generator.generate();
        setUpClients(clientId, "uaa.resource", "uaa.none", "client_credentials", true);
    }

    // ------------------------------------------------------------------------------------
    // Group A -- the happy path, and the exact shape of what gets signed
    // ------------------------------------------------------------------------------------

    @Nested
    @DisplayName("A. successful JWT-SVID issuance")
    class SuccessfulIssuance {

        @Test
        @DisplayName("A1. a valid request returns a JWT-SVID whose claims follow the SPIFFE JWT-SVID spec")
        void validRequestIssuesSpecConformantSvid() throws Exception {
            String org = "org" + generator.generate();
            String space = "space" + generator.generate();
            String app = "app" + generator.generate();
            CertKey instance = SpiffeTestCerts.newInstanceCert(CA, org, space, app);
            String expectedSpiffeId = spiffeId(org, space, app, "web");

            MvcResult result = perform(signRequest(instance, "web", AUDIENCE));
            assertThat(result.getResponse().getStatus()).as("Actual: %s", outcome(result)).isEqualTo(200);

            Map<String, Object> body = bodyOf(result);
            assertThat(body.get("spiffe_id")).isEqualTo(expectedSpiffeId);
            assertThat(body).containsKeys("svid", "spiffe_id", "expires_at");

            Map<String, Object> claims = claimsOf((String) body.get("svid"));
            // SPIFFE JWT-SVID spec: sub MUST be the SPIFFE ID; aud and exp MUST be present.
            assertThat(claims.get("sub")).isEqualTo(expectedSpiffeId);
            // The signer builds aud as a one-element list, but the JWT encoder collapses a
            // single audience to a scalar string. RFC 7519 4.1.3 permits that and the SPIFFE
            // JWT-SVID spec defers to it, so this pins the actual wire shape -- a later move to
            // array-valued aud should be a deliberate choice, not an accident.
            assertThat(claims.get("aud")).isEqualTo(AUDIENCE);
            assertThat(claims).containsKeys("exp", "iat", "jti", "iss");
            assertThat((Integer) claims.get("exp")).isEqualTo(((Number) body.get("expires_at")).intValue());

            @SuppressWarnings("unchecked")
            Map<String, Object> cf = (Map<String, Object>) claims.get("cf");
            assertThat(cf).containsEntry("org_id", org)
                    .containsEntry("space_id", space)
                    .containsEntry("app_id", app)
                    .containsEntry("process_type", "web");
        }

        @Test
        @DisplayName("A2. process_type is reflected in the SPIFFE ID path and the cf claim")
        void processTypeFlowsIntoSpiffeIdAndClaims() throws Exception {
            String org = "org" + generator.generate();
            String space = "space" + generator.generate();
            String app = "app" + generator.generate();
            CertKey instance = SpiffeTestCerts.newInstanceCert(CA, org, space, app);

            MvcResult result = perform(signRequest(instance, "worker", AUDIENCE));
            assertThat(result.getResponse().getStatus()).as("Actual: %s", outcome(result)).isEqualTo(200);

            assertThat(bodyOf(result).get("spiffe_id")).isEqualTo(spiffeId(org, space, app, "worker"));
        }

        @Test
        @DisplayName("A3. the SVID is signed by a key published on /token_keys, enabling offline verification")
        void svidIsSignedByAPublishedKey() throws Exception {
            CertKey instance = SpiffeTestCerts.newInstanceCert(CA, "o", "s", "a");

            String svid = (String) bodyOf(perform(signRequest(instance, "web", AUDIENCE))).get("svid");

            MvcResult keys = mockMvc.perform(get("/token_keys")
                    .accept(APPLICATION_JSON)
                    .header("Authorization", basic(clientId, SECRET))).andReturn();
            assertThat(keys.getResponse().getStatus()).as("Actual: %s", outcome(keys)).isEqualTo(200);
            assertThat(keys.getResponse().getContentAsString())
                    .as("the kid that signed the SVID must be published for offline verification")
                    .contains(headerKidOf(svid));
        }
    }

    // ------------------------------------------------------------------------------------
    // Group B -- who is allowed to call the endpoint at all
    // ------------------------------------------------------------------------------------

    @Nested
    @DisplayName("B. endpoint authentication and authorization")
    class EndpointAuthorization {

        @Test
        @DisplayName("B1. an unauthenticated request is refused")
        void unauthenticatedRequestIsRefused() throws Exception {
            CertKey instance = SpiffeTestCerts.newInstanceCert(CA, "o", "s", "a");

            MvcResult result = mockMvc.perform(post(SIGN_PATH)
                    .accept(APPLICATION_JSON)
                    .contentType(APPLICATION_JSON)
                    .content(requestJson(instance, "web", AUDIENCE))).andReturn();

            assertThat(result.getResponse().getStatus()).as("Actual: %s", outcome(result)).isEqualTo(401);
        }

        @Test
        @DisplayName("B2. a client without the uaa.resource authority is refused")
        void clientWithoutResourceAuthorityIsRefused() throws Exception {
            String weakClient = "weak" + generator.generate();
            setUpClients(weakClient, "uaa.none", "uaa.none", "client_credentials", true);
            CertKey instance = SpiffeTestCerts.newInstanceCert(CA, "o", "s", "a");

            MvcResult result = mockMvc.perform(post(SIGN_PATH)
                    .accept(APPLICATION_JSON)
                    .contentType(APPLICATION_JSON)
                    .header("Authorization", basic(weakClient, SECRET))
                    .content(requestJson(instance, "web", AUDIENCE))).andReturn();

            assertThat(result.getResponse().getStatus())
                    .as("Actual: %s", outcome(result)).isEqualTo(403);
        }

        @Test
        @DisplayName("B3. a bad client secret is refused")
        void badClientSecretIsRefused() throws Exception {
            CertKey instance = SpiffeTestCerts.newInstanceCert(CA, "o", "s", "a");

            MvcResult result = mockMvc.perform(post(SIGN_PATH)
                    .accept(APPLICATION_JSON)
                    .contentType(APPLICATION_JSON)
                    .header("Authorization", basic(clientId, "wrong-secret"))
                    .content(requestJson(instance, "web", AUDIENCE))).andReturn();

            assertThat(result.getResponse().getStatus()).as("Actual: %s", outcome(result)).isEqualTo(401);
        }
    }

    // ------------------------------------------------------------------------------------
    // Group C -- instance certificate verification
    // ------------------------------------------------------------------------------------

    @Nested
    @DisplayName("C. instance certificate verification")
    class CertificateVerification {

        @Test
        @DisplayName("C1. a certificate signed by an untrusted CA is refused")
        void certificateFromUntrustedCaIsRefused() throws Exception {
            CertKey otherCa = SpiffeTestCerts.newCa();
            CertKey instance = SpiffeTestCerts.newInstanceCert(otherCa, "o", "s", "a");

            MvcResult result = perform(signRequest(instance, "web", AUDIENCE));

            assertThat(result.getResponse().getStatus()).as("Actual: %s", outcome(result)).isEqualTo(401);
        }

        @Test
        @DisplayName("C2. an expired instance certificate is refused")
        void expiredCertificateIsRefused() throws Exception {
            CertKey instance = SpiffeTestCerts.newInstanceCert(CA, "o", "s", "a",
                    Instant.now().minus(2, ChronoUnit.DAYS), Instant.now().minus(1, ChronoUnit.DAYS));

            MvcResult result = perform(signRequest(instance, "web", AUDIENCE));

            assertThat(result.getResponse().getStatus()).as("Actual: %s", outcome(result)).isEqualTo(401);
        }

        @Test
        @DisplayName("C3. a not-yet-valid instance certificate is refused")
        void notYetValidCertificateIsRefused() throws Exception {
            CertKey instance = SpiffeTestCerts.newInstanceCert(CA, "o", "s", "a",
                    Instant.now().plus(1, ChronoUnit.DAYS), Instant.now().plus(2, ChronoUnit.DAYS));

            MvcResult result = perform(signRequest(instance, "web", AUDIENCE));

            assertThat(result.getResponse().getStatus()).as("Actual: %s", outcome(result)).isEqualTo(401);
        }

        @Test
        @DisplayName("C4. a malformed certificate PEM is refused as a bad request")
        void malformedCertificatePemIsRefused() throws Exception {
            MvcResult result = perform(signBody(requestJson("not-a-pem", "web", AUDIENCE, 0, "AAAA")));

            assertThat(result.getResponse().getStatus()).as("Actual: %s", outcome(result)).isEqualTo(400);
        }
    }

    // ------------------------------------------------------------------------------------
    // Group D -- proof of possession
    // ------------------------------------------------------------------------------------

    @Nested
    @DisplayName("D. proof-of-possession verification")
    class ProofOfPossession {

        // The PoP is the control that stops a caller who holds only the workload's PUBLIC
        // certificate -- which is not a secret; it travels in TLS handshakes and XFCC headers --
        // from minting that workload's identity. Every test here is that control failing closed.

        @Test
        @DisplayName("D1. a PoP signed with a key other than the certificate's is refused")
        void popSignedByWrongKeyIsRefused() throws Exception {
            CertKey instance = SpiffeTestCerts.newInstanceCert(CA, "o", "s", "a");
            PrivateKey attackerKey = SpiffeTestCerts.newRsaKeyPair().getPrivate();
            long now = Instant.now().getEpochSecond();
            String spiffeId = spiffeId("o", "s", "a", "web");

            MvcResult result = perform(signBody(requestJson(
                    SpiffeTestCerts.certificatePem(instance.certificate()), "web", AUDIENCE, now,
                    pop(attackerKey, spiffeId, AUDIENCE, now))));

            assertThat(result.getResponse().getStatus()).as("Actual: %s", outcome(result)).isEqualTo(401);
        }

        @Test
        @DisplayName("D2. a stale timestamp outside the freshness window is refused")
        void staleTimestampIsRefused() throws Exception {
            CertKey instance = SpiffeTestCerts.newInstanceCert(CA, "o", "s", "a");
            long stale = Instant.now().getEpochSecond() - 3600;
            String spiffeId = spiffeId("o", "s", "a", "web");

            MvcResult result = perform(signBody(requestJson(
                    SpiffeTestCerts.certificatePem(instance.certificate()), "web", AUDIENCE, stale,
                    pop(instance.keyPair().getPrivate(), spiffeId, AUDIENCE, stale))));

            assertThat(result.getResponse().getStatus()).as("Actual: %s", outcome(result)).isEqualTo(401);
        }

        @Test
        @DisplayName("D3. a PoP bound to a different audience than the one requested is refused")
        void popBoundToDifferentAudienceIsRefused() throws Exception {
            CertKey instance = SpiffeTestCerts.newInstanceCert(CA, "o", "s", "a");
            long now = Instant.now().getEpochSecond();
            String spiffeId = spiffeId("o", "s", "a", "web");

            MvcResult result = perform(signBody(requestJson(
                    SpiffeTestCerts.certificatePem(instance.certificate()), "web", AUDIENCE, now,
                    pop(instance.keyPair().getPrivate(), spiffeId, "https://other.example.com", now))));

            assertThat(result.getResponse().getStatus())
                    .as("audience is part of the signed PoP message, so it cannot be swapped. Actual: %s",
                            outcome(result))
                    .isEqualTo(401);
        }

        @Test
        @DisplayName("D4. a PoP bound to a different process_type than the one requested is refused")
        void popBoundToDifferentProcessTypeIsRefused() throws Exception {
            CertKey instance = SpiffeTestCerts.newInstanceCert(CA, "o", "s", "a");
            long now = Instant.now().getEpochSecond();

            MvcResult result = perform(signBody(requestJson(
                    SpiffeTestCerts.certificatePem(instance.certificate()), "web", AUDIENCE, now,
                    pop(instance.keyPair().getPrivate(), spiffeId("o", "s", "a", "worker"), AUDIENCE, now))));

            assertThat(result.getResponse().getStatus())
                    .as("process_type is inside the SPIFFE ID, which is inside the signed PoP message. Actual: %s",
                            outcome(result))
                    .isEqualTo(401);
        }

        @Test
        @DisplayName("D5. a malformed base64 PoP signature is refused")
        void malformedBase64PopIsRefused() throws Exception {
            CertKey instance = SpiffeTestCerts.newInstanceCert(CA, "o", "s", "a");
            long now = Instant.now().getEpochSecond();

            MvcResult result = perform(signBody(requestJson(
                    SpiffeTestCerts.certificatePem(instance.certificate()), "web", AUDIENCE, now, "!!!not-base64!!!")));

            assertThat(result.getResponse().getStatus()).as("Actual: %s", outcome(result)).isEqualTo(401);
        }
    }

    // ------------------------------------------------------------------------------------
    // Group E -- request field validation
    // ------------------------------------------------------------------------------------

    @Nested
    @DisplayName("E. request field validation")
    class RequestValidation {

        @Test
        @DisplayName("E1. a process_type containing a path separator is refused")
        void processTypeWithPathSeparatorIsRefused() throws Exception {
            CertKey instance = SpiffeTestCerts.newInstanceCert(CA, "o", "s", "a");

            MvcResult result = perform(signRequest(instance, "web/../admin", AUDIENCE));

            assertThat(result.getResponse().getStatus())
                    .as("process_type is concatenated into the SPIFFE ID path. Actual: %s", outcome(result))
                    .isEqualTo(400);
        }

        @Test
        @DisplayName("E2. a blank audience is refused")
        void blankAudienceIsRefused() throws Exception {
            CertKey instance = SpiffeTestCerts.newInstanceCert(CA, "o", "s", "a");

            MvcResult result = perform(signRequest(instance, "web", "  "));

            assertThat(result.getResponse().getStatus()).as("Actual: %s", outcome(result)).isEqualTo(400);
        }

        @Test
        @DisplayName("E3. an over-long audience is refused")
        void overLongAudienceIsRefused() throws Exception {
            CertKey instance = SpiffeTestCerts.newInstanceCert(CA, "o", "s", "a");

            MvcResult result = perform(signRequest(instance, "web", "a".repeat(513)));

            assertThat(result.getResponse().getStatus()).as("Actual: %s", outcome(result)).isEqualTo(400);
        }

        @Test
        @DisplayName("E4. an audience containing a newline is refused")
        void audienceWithControlCharacterIsRefused() throws Exception {
            CertKey instance = SpiffeTestCerts.newInstanceCert(CA, "o", "s", "a");

            MvcResult result = perform(signRequest(instance, "web", "aud\nspiffe://cf.example.com/evil"));

            assertThat(result.getResponse().getStatus())
                    .as("a newline would make the signed PoP message ambiguous. Actual: %s", outcome(result))
                    .isEqualTo(400);
        }

        @Test
        @DisplayName("E5. the configured CA's own certificate is refused at chain verification")
        void theCaCertificateItselfIsRefused() throws Exception {
            // A self-signed CA certificate verifies against its own public key, so a raw
            // "signed by the CA key" check cannot tell it apart from a leaf the CA issued.
            // It must be refused as untrusted (401) at verification, not merely stumble later
            // on its missing CF OUs -- otherwise the trust anchor doubles as a usable identity.
            MvcResult result = perform(signBody(requestJson(
                    SpiffeTestCerts.certificatePem(CA.certificate()), "web", AUDIENCE,
                    Instant.now().getEpochSecond(), "AAAA")));

            assertThat(result.getResponse().getStatus())
                    .as("Actual: %s", outcome(result))
                    .isEqualTo(401);
        }

        @Test
        @DisplayName("E6. a certificate whose OU values would break out of the SPIFFE ID path is refused")
        void certificateWithPathInjectingOuIsRefused() throws Exception {
            // process_type is strictly validated because it lands in the SPIFFE ID path, but the
            // org/space/app OUs land in the very same path and come from the certificate. A cert
            // carrying a '/' in an OU must not be able to forge a different SPIFFE ID, and a
            // newline must not be able to make the signed PoP message ambiguous.
            CertKey instance = SpiffeTestCerts.newInstanceCert(CA, "o", "s", "a/process/admin");

            MvcResult result = perform(signRequest(instance, "web", AUDIENCE));

            assertThat(result.getResponse().getStatus())
                    .as("SPIFFE ID path segments may contain only [a-zA-Z0-9.-_]. Actual: %s", outcome(result))
                    .isEqualTo(400);
        }
    }

    // ------------------------------------------------------------------------------------
    // Group F -- a JWT-SVID must not double as a UAA access token
    // ------------------------------------------------------------------------------------

    @Nested
    @DisplayName("F. JWT-SVIDs are not usable as UAA access tokens")
    class SvidIsNotAnAccessToken {

        // A JWT-SVID is signed with the SAME key, carries the SAME iss, and has the same
        // typ/kid header as a real UAA access token -- the claim set is the only thing telling
        // the two populations apart. These tests pin the claims that keep them apart, so a
        // future change that adds a client_id/scope claim to the SVID cannot pass silently.

        @Test
        @DisplayName("F1. a JWT-SVID carries no client_id, cid, scope or user_id claim")
        void svidCarriesNoAuthorizationClaims() throws Exception {
            CertKey instance = SpiffeTestCerts.newInstanceCert(CA, "o", "s", "a");

            MvcResult result = perform(signRequest(instance, "web", AUDIENCE));
            Map<String, Object> claims = claimsOf((String) bodyOf(result).get("svid"));

            assertThat(claims)
                    .as("Actual claims: %s", claims)
                    .doesNotContainKeys("client_id", "cid", "scope", "user_id", "authorities", "grant_type");
        }

        @Test
        @DisplayName("F2. UAA's own introspection rejects a JWT-SVID")
        void introspectionRejectsSvid() throws Exception {
            CertKey instance = SpiffeTestCerts.newInstanceCert(CA, "o", "s", "a");
            String svid = (String) bodyOf(perform(signRequest(instance, "web", AUDIENCE))).get("svid");

            MvcResult result = mockMvc.perform(post("/introspect")
                    .accept(APPLICATION_JSON)
                    .contentType(APPLICATION_FORM_URLENCODED)
                    .header("Authorization", basic(clientId, SECRET))
                    .param("token", svid)).andReturn();

            assertThat(result.getResponse().getContentAsString())
                    .as("a JWT-SVID bears no client ID, so it cannot resolve to an OAuth authorization")
                    .doesNotContain("\"active\":true");
        }
    }

    // ------------------------------------------------------------------------------------
    // helpers
    // ------------------------------------------------------------------------------------

    private MvcResult perform(MockHttpServletRequestBuilder request) throws Exception {
        return mockMvc.perform(request).andReturn();
    }

    private MockHttpServletRequestBuilder signRequest(CertKey instance, String processType, String audience) {
        long timestamp = Instant.now().getEpochSecond();
        String spiffeId = spiffeIdOf(instance, processType);
        return signBody(requestJson(SpiffeTestCerts.certificatePem(instance.certificate()), processType, audience,
                timestamp, pop(instance.keyPair().getPrivate(), spiffeId, audience, timestamp)));
    }

    private MockHttpServletRequestBuilder signBody(String json) {
        return post(SIGN_PATH)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .header("Authorization", basic(clientId, SECRET))
                .content(json);
    }

    private String requestJson(CertKey instance, String processType, String audience) {
        long timestamp = Instant.now().getEpochSecond();
        return requestJson(SpiffeTestCerts.certificatePem(instance.certificate()), processType, audience, timestamp,
                pop(instance.keyPair().getPrivate(), spiffeIdOf(instance, processType), audience, timestamp));
    }

    private static String requestJson(String certificatePem, String processType, String audience,
                                      long timestamp, String popSignature) {
        Map<String, Object> request = new LinkedHashMap<>();
        request.put("instance_certificate", certificatePem);
        request.put("process_type", processType);
        request.put("audience", audience);
        request.put("timestamp", timestamp);
        request.put("pop_signature", popSignature);
        return JsonUtils.writeValueAsString(request);
    }

    /** Reads the OUs back out of the cert so the PoP binds to whatever UAA will compute. */
    private static String spiffeIdOf(CertKey instance, String processType) {
        String subject = instance.certificate().getSubjectX500Principal().getName();
        return spiffeId(ouValue(subject, "organization:"), ouValue(subject, "space:"),
                ouValue(subject, "app:"), processType);
    }

    private static String ouValue(String subjectDn, String prefix) {
        // Diego puts org/space/app in a single multi-valued RDN, so components are separated
        // by '+' within an RDN and ',' between RDNs.
        for (String part : subjectDn.split("[,+]")) {
            String trimmed = part.trim();
            int equals = trimmed.indexOf('=');
            if (equals < 0) {
                continue;
            }
            String value = trimmed.substring(equals + 1);
            if (value.startsWith(prefix)) {
                return value.substring(prefix.length());
            }
        }
        throw new IllegalStateException("No OU with prefix " + prefix + " in " + subjectDn);
    }

    private static String spiffeId(String org, String space, String app, String processType) {
        return "spiffe://" + TRUST_DOMAIN + "/cf/org/" + org + "/space/" + space
                + "/app/" + app + "/process/" + processType;
    }

    /** Signs the exact message {@code ProofOfPossessionVerifier} reconstructs. */
    private static String pop(PrivateKey key, String spiffeId, String audience, long timestamp) {
        try {
            Signature signature = Signature.getInstance("SHA256withRSA", BouncyCastleFipsProvider.PROVIDER_NAME);
            signature.initSign(key);
            signature.update((spiffeId + "\n" + audience + "\n" + timestamp).getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(signature.sign());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static String basic(String clientId, String secret) {
        return "Basic " + Base64.getEncoder()
                .encodeToString((clientId + ":" + secret).getBytes(StandardCharsets.UTF_8));
    }

    private static Map<String, Object> bodyOf(MvcResult result) throws Exception {
        return JsonUtils.readValue(result.getResponse().getContentAsString(),
                new TypeReference<Map<String, Object>>() {
                });
    }

    private static Map<String, Object> claimsOf(String jwt) {
        return JsonUtils.readValue(JwtHelper.decode(jwt).getClaims(),
                new TypeReference<Map<String, Object>>() {
                });
    }

    private static String headerKidOf(String jwt) {
        String header = new String(Base64.getUrlDecoder().decode(jwt.substring(0, jwt.indexOf('.'))),
                StandardCharsets.UTF_8);
        Map<String, Object> parsed = JsonUtils.readValue(header, new TypeReference<Map<String, Object>>() {
        });
        return (String) parsed.get("kid");
    }

    /** Builds assertion-failure text that shows what the endpoint actually said. */
    private static String outcome(MvcResult result) throws Exception {
        String content = result.getResponse().getContentAsString();
        return "status=" + result.getResponse().getStatus() + ", body="
                + ((content == null || content.isBlank()) ? "<empty>" : content);
    }

}
