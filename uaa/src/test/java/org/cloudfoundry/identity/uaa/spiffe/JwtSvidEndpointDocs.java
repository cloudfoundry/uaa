package org.cloudfoundry.identity.uaa.spiffe;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.cloudfoundry.identity.uaa.mock.EndpointDocs;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.util.AlphanumericRandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.env.MapPropertySource;
import org.springframework.restdocs.snippet.Snippet;
import org.springframework.test.context.ContextConfiguration;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.Signature;
import java.time.Instant;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.restdocs.headers.HeaderDocumentation.headerWithName;
import static org.springframework.restdocs.headers.HeaderDocumentation.requestHeaders;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.post;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.preprocessRequest;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.preprocessResponse;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.prettyPrint;
import static org.springframework.restdocs.payload.JsonFieldType.NUMBER;
import static org.springframework.restdocs.payload.JsonFieldType.STRING;
import static org.springframework.restdocs.payload.PayloadDocumentation.fieldWithPath;
import static org.springframework.restdocs.payload.PayloadDocumentation.requestFields;
import static org.springframework.restdocs.payload.PayloadDocumentation.responseFields;
import static org.springframework.restdocs.snippet.Attributes.key;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Generates the Slate documentation for {@code POST /jwt-svid/sign}.
 *
 * <p>Every SPIFFE bean is gated behind {@code @ConditionalOnProperty("uaa.spiffe.instance-identity-ca")},
 * so {@link SpiffeEnabled} supplies a runtime-generated CA before the context refreshes.
 */
@ContextConfiguration(initializers = JwtSvidEndpointDocs.SpiffeEnabled.class)
class JwtSvidEndpointDocs extends EndpointDocs {

    private static final String TRUST_DOMAIN = "cf.example.com";
    private static final SpiffeTestCerts.CertKey CA = SpiffeTestCerts.newCa();

    static class SpiffeEnabled implements ApplicationContextInitializer<ConfigurableApplicationContext> {
        @Override
        public void initialize(ConfigurableApplicationContext applicationContext) {
            Map<String, Object> properties = new HashMap<>();
            properties.put("uaa.spiffe.instance-identity-ca", SpiffeTestCerts.certificatePem(CA.certificate()));
            properties.put("uaa.spiffe.trust-domain", TRUST_DOMAIN);
            applicationContext.getEnvironment().getPropertySources()
                    .addFirst(new MapPropertySource("spiffeDocsProperties", properties));
        }
    }

    private final AlphanumericRandomValueStringGenerator generator = new AlphanumericRandomValueStringGenerator();
    private String basicAuth;

    @BeforeEach
    void setUp() throws Exception {
        String adminToken = MockMvcUtils.getClientCredentialsOAuthAccessToken(mockMvc, "admin", "adminsecret",
                "clients.read clients.write clients.secret clients.admin", null);
        String clientId = generator.generate().toLowerCase();
        String clientSecret = generator.generate().toLowerCase();
        MockMvcUtils.createClient(mockMvc, adminToken, clientId, clientSecret, null,
                Collections.singletonList("uaa.none"), Collections.singletonList("client_credentials"),
                "uaa.resource");
        basicAuth = "Basic " + Base64.getEncoder()
                .encodeToString((clientId + ":" + clientSecret).getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void signJwtSvid() throws Exception {
        String orgId = "2b8e4a1c-2b52-4a3f-9e4e-1f2c3d4e5f60";
        String spaceId = "7c3a9d2e-5b61-4c8a-9f0d-6a7b8c9d0e1f";
        String appId = "9f1b2c3d-4e5f-4a6b-8c9d-0e1f2a3b4c5d";
        SpiffeTestCerts.CertKey instance = SpiffeTestCerts.newInstanceCert(CA, orgId, spaceId, appId);

        String processType = "web";
        String audience = "https://iam.example.com/projects/1/locations/global/workloadIdentityPools/cf";
        long timestamp = Instant.now().getEpochSecond();
        String spiffeId = "spiffe://" + TRUST_DOMAIN + "/cf/org/" + orgId + "/space/" + spaceId
                + "/app/" + appId + "/process/" + processType;

        Map<String, Object> request = new LinkedHashMap<>();
        request.put("instance_certificate", SpiffeTestCerts.certificatePem(instance.certificate()));
        request.put("process_type", processType);
        request.put("audience", audience);
        request.put("timestamp", timestamp);
        request.put("pop_signature",
                proofOfPossession(instance.keyPair().getPrivate(), spiffeId, audience, timestamp));

        Snippet requestFields = requestFields(
                fieldWithPath("instance_certificate")
                        .attributes(key("constraints").value("Required"))
                        .type(STRING)
                        .description("PEM-encoded Diego instance-identity certificate (`instance.crt`) of the "
                                + "workload the SVID is being requested for. Must be signed directly by the CA "
                                + "configured in `uaa.spiffe.instance_identity_ca`, must currently be within its "
                                + "validity window, and must carry the `organization:`, `space:` and `app:` OU "
                                + "attributes. A certificate is not a secret on its own -- possession of the "
                                + "matching private key is proven separately via `pop_signature`."),
                fieldWithPath("process_type")
                        .attributes(key("constraints").value("Required"))
                        .type(STRING)
                        .description("Process type of the workload, e.g. `web`, `worker` or `ssh`. Becomes the "
                                + "final path segment of the SPIFFE ID. Must match `[A-Za-z0-9_-]{1,63}`."),
                fieldWithPath("audience")
                        .attributes(key("constraints").value("Required"))
                        .type(STRING)
                        .description("The single intended recipient of the SVID, placed in the `aud` claim. The "
                                + "SPIFFE JWT-SVID specification strongly recommends scoping a token to one "
                                + "audience to limit replay. Must be non-blank, at most 512 characters, and free "
                                + "of control characters."),
                fieldWithPath("timestamp")
                        .attributes(key("constraints").value("Required"))
                        .type(NUMBER)
                        .description("Unix epoch seconds at which `pop_signature` was produced. Must be within "
                                + "`uaa.spiffe.pop_freshness_seconds` of UAA's clock, in either direction."),
                fieldWithPath("pop_signature")
                        .attributes(key("constraints").value("Required"))
                        .type(STRING)
                        .description("Base64-encoded proof of possession of the instance private key. Sign the "
                                + "UTF-8 bytes of the newline-joined message `<spiffe_id>\\n<audience>\\n"
                                + "<timestamp>` using `SHA256withECDSA` or `SHA256withRSA` to match the "
                                + "certificate's key type. Because the SPIFFE ID and audience are inside the "
                                + "signed message, neither can be substituted after the fact.")
        );

        Snippet responseFields = responseFields(
                fieldWithPath("svid").type(STRING)
                        .description("The signed JWT-SVID, in JWS compact serialization. Signed with UAA's active "
                                + "token-signing key, so it can be verified offline against `/token_keys`. Its "
                                + "`sub` is the SPIFFE ID, and it additionally carries a `cf` claim holding "
                                + "`org_id`, `space_id`, `app_id` and `process_type`."),
                fieldWithPath("spiffe_id").type(STRING)
                        .description("The SPIFFE ID the SVID was issued for, identical to the token's `sub` claim."),
                fieldWithPath("expires_at").type(NUMBER)
                        .description("Unix epoch seconds at which the SVID expires, identical to the token's `exp` "
                                + "claim. Controlled by `uaa.spiffe.jwt_svid_ttl_seconds`.")
        );

        mockMvc.perform(post("/jwt-svid/sign")
                        .header("Authorization", basicAuth)
                        .accept(APPLICATION_JSON)
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andDo(document("{ClassName}/{methodName}",
                        preprocessRequest(prettyPrint()),
                        preprocessResponse(prettyPrint()),
                        requestHeaders(
                                headerWithName("Authorization")
                                        .description("Basic authentication for a UAA client holding the "
                                                + "`uaa.resource` authority -- the SPIFFE Agent's own identity, "
                                                + "which is unrelated to the workload being attested.")
                        ),
                        requestFields,
                        responseFields));
    }

    private static String proofOfPossession(PrivateKey key, String spiffeId, String audience, long timestamp) {
        try {
            Signature signature = Signature.getInstance("SHA256withRSA", BouncyCastleFipsProvider.PROVIDER_NAME);
            signature.initSign(key);
            signature.update((spiffeId + "\n" + audience + "\n" + timestamp).getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(signature.sign());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
