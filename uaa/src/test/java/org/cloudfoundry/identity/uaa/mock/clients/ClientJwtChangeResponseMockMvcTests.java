package org.cloudfoundry.identity.uaa.mock.clients;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.client.ClientJwtConfiguration;
import org.cloudfoundry.identity.uaa.client.UaaClient;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.oauth.client.ClientJwtChangeRequest;
import org.cloudfoundry.identity.uaa.oauth.client.ClientJwtCredential;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.MultitenantJdbcClientDetailsService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for the response of PUT /oauth/clients/{id}/clientjwt, which lists the key ids ({@code kids}), the
 * {@code jwks_uri} and the federated credentials ({@code jwt_creds}) of the client after the change.
 * <p>
 * The docs (docs/UAA-Client-Authentication.md, ClientAdminEndpointDocs) say that a caller compares the lists with the
 * state it wants and sends the change again if needed. The tests below cover changes whose outcome the response did
 * not show, or showed in a way that a retry could not fix. Each has a comment with the reason and the decision.
 */
@DefaultTestContext
class ClientJwtChangeResponseMockMvcTests {

    // two different RSA moduli under the same kid
    private static final String MODULUS_STORED = "u_A1S-WoVAnHlNQ_1HJmOPBVxIdy1uSNsp5JUF5N4KtOjir9EgG9HhCFRwz48ykEukrgaK4ofyy_wRXSUJKW7Q";
    private static final String MODULUS_SENT = "xjlCRBqkOyLEEWzk6vOmrvBg4yVLm8PSW5W3j4kVWwEk1bEGVsDoKiCfqD7oUcAxhcSBKpTRnF4mbdbEhHlR5Q";
    private static final String LEGACY_ISSUER = "https://legacy.example.com";
    private static final String OTHER_LEGACY_ISSUER = "https://other-legacy.example.com";
    private static final String LEGACY_SUBJECT = "legacy-subject";

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private TestClient testClient;
    @Autowired
    private JdbcTemplate jdbcTemplate;
    // a spy, so that one test can hold a request; the others use it as it is
    @MockitoSpyBean
    private MultitenantJdbcClientDetailsService clientService;

    private String adminToken;

    @BeforeEach
    void setUp() throws Exception {
        adminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret", "uaa.admin,clients.secret");
    }

    /*
     * kids show the key id, not the key.
     *
     * JsonWebKey.equals compares the kid only, so ClientJwtConfiguration.merge treats a key whose kid is already
     * stored as already present: an ADD keeps the stored key and drops the one sent. The endpoint answers 200
     * "Client jwt configuration is added", and the response lists key-1. This is older than the response lists.
     *
     * Decision: docs only. The docs say that kids confirm the key id, not the key, and that UPDATE replaces the key
     * of a kid (see the guard below). This test pins the documented behavior.
     */
    @Test
    void addOfAKidThatIsStoredKeepsTheStoredKey() throws Exception {
        String clientId = createClient();
        change(clientId, ClientJwtChangeRequest.ChangeMode.ADD, keys("key-1", MODULUS_STORED));

        MvcResult result = change(clientId, ClientJwtChangeRequest.ChangeMode.ADD, keys("key-1", MODULUS_SENT));

        assertThat(result.getResponse().getStatus()).isEqualTo(200);
        assertThat(kidsOf(body(result))).containsExactly("key-1");
        assertThat(storedModulus(clientId, "key-1")).as("the key stored under key-1").isEqualTo(MODULUS_STORED);
    }

    // Guard: UPDATE replaces the key that is stored under the same kid.
    @Test
    void updateOfAKidThatIsStoredReplacesTheKey() throws Exception {
        String clientId = createClient();
        change(clientId, ClientJwtChangeRequest.ChangeMode.ADD, keys("key-1", MODULUS_STORED));

        MvcResult result = change(clientId, ClientJwtChangeRequest.ChangeMode.UPDATE, keys("key-1", MODULUS_SENT));

        assertThat(result.getResponse().getStatus()).isEqualTo(200);
        assertThat(storedModulus(clientId, "key-1")).isEqualTo(MODULUS_SENT);
    }

    /*
     * The response has no jwks_uri.
     *
     * A client can trust a jwks_uri instead of a key set, and PUT /oauth/clients/{id}/clientjwt changes it like a key
     * set. The response lists kids and jwt_creds only, so for a jwks_uri it has empty lists whatever the outcome.
     * Here an ADD of a second jwks_uri keeps the stored one (merge without overwrite) and answers 200 "Client jwt
     * configuration is added". A read of the client shows the stored jwks_uri, the response of the change does not.
     * The docs say the response lists the configuration "the same as a read of the client returns".
     *
     * Expected: the response contains the jwks_uri in effect (omitted when there is none). Failed before the fix: the
     * field was missing.
     */
    @Test
    void responseOfAJwksUriChangeShowsTheJwksUriInEffect() throws Exception {
        String clientId = createClient();
        change(clientId, ClientJwtChangeRequest.ChangeMode.ADD, jwksUri("https://first.example.com/token_keys"));

        MvcResult result = change(clientId, ClientJwtChangeRequest.ChangeMode.ADD, jwksUri("https://second.example.com/token_keys"));

        assertThat(read(clientId)).as("a read of the client").containsEntry("jwks_uri", "https://first.example.com/token_keys");
        assertThat(body(result)).as("the response of the change").containsEntry("jwks_uri", "https://first.example.com/token_keys");
    }

    // A jwks_uri can carry user information, which can hold a password. The response leaves it out and keeps the rest
    // of the address (path and query) as stored.
    @Test
    void responseOfAJwksUriChangeLeavesOutUserInformation() throws Exception {
        String clientId = createClient();

        MvcResult result = change(clientId, ClientJwtChangeRequest.ChangeMode.ADD,
                jwksUri("https://keys-user:keys-password@first.example.com/token_keys?tenant=a"));

        assertThat(result.getResponse().getStatus()).isEqualTo(200);
        assertThat(body(result)).containsEntry("jwks_uri", "https://first.example.com/token_keys?tenant=a");
        assertThat(result.getResponse().getContentAsString()).doesNotContain("keys-user", "keys-password");
    }

    // Guard: the response of a key set change has the key ids only, no key material, and no jwks_uri field.
    @Test
    void responseOfAKeySetChangeHasNoKeyMaterial() throws Exception {
        String clientId = createClient();

        MvcResult result = change(clientId, ClientJwtChangeRequest.ChangeMode.ADD, keys("key-1", MODULUS_STORED));

        assertThat(body(result)).containsOnlyKeys("status", "message", "kids", "jwt_creds");
        assertThat(kidsOf(body(result))).containsExactly("key-1");
        assertThat(result.getResponse().getContentAsString()).doesNotContain(MODULUS_STORED);
    }

    /*
     * A delete of a credential in the older form is answered as done, and the response still lists it.
     *
     * Older UAA versions kept federated credentials as jwt_creds in the additional information of a client. They are
     * still in effect (UaaClient merges them), and the response lists them since the last commit of this PR. A DELETE
     * through this endpoint changes client_jwt_config only, so it answers 200 "Federated client jwt configuration is
     * deleted" and the credential stays. The docs tell the caller to send the change again if needed; the same
     * delete never takes effect.
     *
     * How the PR causes it: the delete was ineffective before as well, but without the lists the caller could not
     * see it. The PR shows it and suggests a retry that cannot succeed.
     *
     * Expected: after a 200 delete, the credential is no longer in effect and the response no longer lists it. Failed
     * before the fix. Fix: the delete also removes the credential from the additional information.
     */
    @Test
    void deleteOfAFederatedCredentialInTheOlderFormNoLongerListsIt() throws Exception {
        String clientId = createClient();
        storeAdditionalInformation(clientId, Map.of(ClientJwtConfiguration.JWT_CREDS, List.of(legacyCredential(LEGACY_ISSUER))));

        MvcResult result = change(clientId, ClientJwtChangeRequest.ChangeMode.DELETE, federated(LEGACY_ISSUER, LEGACY_SUBJECT));

        assertThat(result.getResponse().getStatus()).isEqualTo(200);
        assertThat(body(result)).containsEntry("message", "Federated client jwt configuration is deleted");
        assertThat(issuersOf(body(result))).doesNotContain(LEGACY_ISSUER);
        assertThat(issuersInEffect(clientId)).doesNotContain(LEGACY_ISSUER);
    }

    // Guard: the delete removes only the credential it names. Other credentials in the older form and the other
    // fields of the additional information stay.
    @Test
    void deleteOfAFederatedCredentialInTheOlderFormKeepsTheOtherEntries() throws Exception {
        String clientId = createClient();
        storeAdditionalInformation(clientId, Map.of("name", "kept", ClientJwtConfiguration.JWT_CREDS,
                List.of(legacyCredential(LEGACY_ISSUER), legacyCredential(OTHER_LEGACY_ISSUER))));

        MvcResult result = change(clientId, ClientJwtChangeRequest.ChangeMode.DELETE, federated(LEGACY_ISSUER, LEGACY_SUBJECT));

        assertThat(issuersOf(body(result))).containsExactly(OTHER_LEGACY_ISSUER);
        assertThat(issuersInEffect(clientId)).containsExactly(OTHER_LEGACY_ISSUER);
        assertThat(storedAdditionalInformation(clientId)).containsEntry("name", "kept");
    }

    // The delete writes the additional information only if it is still the value it read. Here a general update of the
    // client lands between that read and the write; the delete must not replace it. The request is held when it
    // writes client_jwt_config, which is after the read and before the write of the additional information.
    @Test
    void deleteOfAFederatedCredentialInTheOlderFormDoesNotReplaceAGeneralUpdateInTheMeantime() throws Exception {
        String clientId = createClient();
        storeAdditionalInformation(clientId, Map.of(ClientJwtConfiguration.JWT_CREDS, List.of(legacyCredential(LEGACY_ISSUER))));
        CountDownLatch held = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        doAnswer(invocation -> {
            boolean inDelete = Arrays.stream(Thread.currentThread().getStackTrace())
                    .anyMatch(frame -> frame.getMethodName().equals("deleteClientJwtCredential"));
            if (inDelete) {
                held.countDown();
                assertThat(release.await(30, TimeUnit.SECONDS)).as("released").isTrue();
            }
            return invocation.callRealMethod();
        }).when(clientService).updateClientJwtConfig(eq(clientId), any(), anyString());

        try (ExecutorService executor = Executors.newSingleThreadExecutor()) {
            Future<MvcResult> delete = executor.submit(() ->
                    change(clientId, ClientJwtChangeRequest.ChangeMode.DELETE, federated(LEGACY_ISSUER, LEGACY_SUBJECT)));
            try {
                assertThat(held.await(30, TimeUnit.SECONDS)).as("the delete has read the additional information").isTrue();
                generalUpdate(clientId, Map.of("name", "renamed"));
            } finally {
                release.countDown();
            }
            assertThat(delete.get(30, TimeUnit.SECONDS).getResponse().getStatus()).isEqualTo(200);
        }
        assertThat(storedAdditionalInformation(clientId)).containsEntry("name", "renamed");
    }

    private String createClient() throws Exception {
        String clientId = "jwt-response-" + UUID.randomUUID().toString().substring(0, 8);
        UaaClientDetails client = new UaaClientDetails(clientId, null, "uaa.none", "client_credentials", "uaa.none");
        client.setClientSecret("secret");
        mockMvc.perform(post("/oauth/clients")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(client)))
                .andExpect(status().isCreated());
        return clientId;
    }

    private MvcResult change(String clientId, ClientJwtChangeRequest.ChangeMode mode, ClientJwtChangeRequest request) throws Exception {
        request.setClientId(clientId);
        request.setChangeMode(mode);
        return mockMvc.perform(put("/oauth/clients/{client_id}/clientjwt", clientId)
                        .header("Authorization", "Bearer " + adminToken)
                        .accept(APPLICATION_JSON)
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(request)))
                .andReturn();
    }

    private static ClientJwtChangeRequest keys(String kid, String modulus) {
        return new ClientJwtChangeRequest(null, null,
                "{\"keys\":[{\"kty\":\"RSA\",\"e\":\"AQAB\",\"kid\":\"" + kid + "\",\"alg\":\"RS256\",\"n\":\"" + modulus + "\"}]}");
    }

    private static ClientJwtChangeRequest jwksUri(String uri) {
        return new ClientJwtChangeRequest(null, uri, null);
    }

    private static ClientJwtChangeRequest federated(String issuer, String subject) {
        ClientJwtChangeRequest request = new ClientJwtChangeRequest();
        request.setIssuer(issuer);
        request.setSubject(subject);
        return request;
    }

    private static Map<String, Object> legacyCredential(String issuer) {
        return Map.of("iss", issuer, "sub", LEGACY_SUBJECT);
    }

    // The older form: jwt_creds in the additional information, written as older UAA versions stored it.
    private void storeAdditionalInformation(String clientId, Map<String, Object> additionalInformation) {
        assertThat(jdbcTemplate.update("update oauth_client_details set additional_information=? where client_id=? and identity_zone_id='uaa'",
                JsonUtils.writeValueAsString(additionalInformation), clientId)).isEqualTo(1);
        assertThat(issuersInEffect(clientId)).as("precondition: the credentials are in effect").isNotEmpty();
    }

    private Map<String, Object> storedAdditionalInformation(String clientId) {
        return JsonUtils.readValueAsMap(jdbcTemplate.queryForObject(
                "select additional_information from oauth_client_details where client_id=? and identity_zone_id='uaa'", String.class, clientId));
    }

    // A general update of the client (PUT /oauth/clients/{id}) that sets the additional information.
    private void generalUpdate(String clientId, Map<String, Object> additionalInformation) throws Exception {
        UaaClientDetails update = new UaaClientDetails(clientId, null, "uaa.none", "client_credentials", "uaa.none");
        update.setAdditionalInformation(additionalInformation);
        mockMvc.perform(put("/oauth/clients/{client_id}", clientId)
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(APPLICATION_JSON)
                        .accept(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(update)))
                .andExpect(status().isOk());
    }

    // The federated credentials that client authentication uses.
    private List<String> issuersInEffect(String clientId) {
        UaaClientDetails details = (UaaClientDetails) clientService.loadClientByClientId(clientId, "uaa");
        ClientJwtConfiguration inEffect = new UaaClient(details.getClientId(), details.getClientSecret(), details.getAuthorities(),
                new HashMap<>(Optional.ofNullable(details.getAdditionalInformation()).orElseGet(Map::of)),
                details.getClientJwtConfig()).getClientJwtConfiguration();
        return inEffect.getClientJwtCredentials() == null ? List.of() :
                inEffect.getClientJwtCredentials().stream().map(ClientJwtCredential::getIssuer).toList();
    }

    private String storedClientJwtConfig(String clientId) {
        return jdbcTemplate.queryForObject(
                "select client_jwt_config from oauth_client_details where client_id=? and identity_zone_id='uaa'", String.class, clientId);
    }

    private String storedModulus(String clientId, String kid) {
        return ClientJwtConfiguration.readValue(storedClientJwtConfig(clientId)).getJwkSet().getKeys().stream()
                .filter(key -> kid.equals(key.getKid()))
                .map(JsonWebKey::getKeyProperties)
                .map(properties -> (String) properties.get("n"))
                .findFirst().orElseThrow();
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> read(String clientId) throws Exception {
        String content = mockMvc.perform(get("/oauth/clients/{client_id}", clientId)
                        .header("Authorization", "Bearer " + adminToken)
                        .accept(APPLICATION_JSON))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return JsonUtils.readValue(content, Map.class);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> body(MvcResult result) throws Exception {
        return JsonUtils.readValue(result.getResponse().getContentAsString(), Map.class);
    }

    @SuppressWarnings("unchecked")
    private static List<String> kidsOf(Map<String, Object> body) {
        return (List<String>) body.get("kids");
    }

    @SuppressWarnings("unchecked")
    private static List<String> issuersOf(Map<String, Object> body) {
        return ((List<Map<String, Object>>) body.get("jwt_creds")).stream().map(credential -> (String) credential.get("iss")).toList();
    }
}
