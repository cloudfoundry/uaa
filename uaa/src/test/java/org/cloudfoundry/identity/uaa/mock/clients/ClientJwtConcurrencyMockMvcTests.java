package org.cloudfoundry.identity.uaa.mock.clients;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.client.ClientJwtConfiguration;
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

import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Two changes of the jwt configuration of one client that arrive at the same time, through
 * PUT /oauth/clients/{id}/clientjwt.
 */
@DefaultTestContext
class ClientJwtConcurrencyMockMvcTests {

    private static final String N = "u_A1S-WoVAnHlNQ_1HJmOPBVxIdy1uSNsp5JUF5N4KtOjir9EgG9HhCFRwz48ykEukrgaK4ofyy_wRXSUJKW7Q";

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private TestClient testClient;
    @Autowired
    private JdbcTemplate jdbcTemplate;
    @MockitoSpyBean
    private MultitenantJdbcClientDetailsService clientService;

    private String token;

    @BeforeEach
    void setUp() throws Exception {
        token = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret", "uaa.admin,clients.secret");
    }

    private String createClient() throws Exception {
        String clientId = "jwt-race-" + UUID.randomUUID().toString().substring(0, 8);
        UaaClientDetails client = new UaaClientDetails(clientId, null, "uaa.none", "client_credentials", "uaa.none");
        client.setClientSecret("secret");
        mockMvc.perform(post("/oauth/clients")
                        .header("Authorization", "Bearer " + token)
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(client)))
                .andExpect(status().isCreated());
        return clientId;
    }

    private Callable<MvcResult> change(String clientId, ClientJwtChangeRequest request) {
        request.setClientId("admin");
        request.setChangeMode(ClientJwtChangeRequest.ChangeMode.ADD);
        return () -> mockMvc.perform(put("/oauth/clients/{client_id}/clientjwt", clientId)
                        .header("Authorization", "Bearer " + token)
                        .accept(APPLICATION_JSON)
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andReturn();
    }

    // Holds each of the two requests right after it has loaded the client for its jwt change, until both have loaded
    // (or 3 seconds have passed, which lets a fix that serializes the changes finish).
    private List<Map<String, Object>> runBothAfterBothHaveLoaded(String clientId, Callable<MvcResult> firstChange, Callable<MvcResult> secondChange) throws Exception {
        CountDownLatch bothHaveLoaded = new CountDownLatch(2);
        doAnswer(invocation -> {
            Object loaded = invocation.callRealMethod();
            boolean inJwtChange = java.util.Arrays.stream(Thread.currentThread().getStackTrace())
                    .anyMatch(frame -> frame.getMethodName().startsWith("addClientJwt"));
            if (inJwtChange) {
                bothHaveLoaded.countDown();
                bothHaveLoaded.await(3, TimeUnit.SECONDS);
            }
            return loaded;
        }).when(clientService).loadClientByClientId(eq(clientId), anyString());
        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            Future<MvcResult> first = executor.submit(firstChange);
            Future<MvcResult> second = executor.submit(secondChange);
            return List.of(
                    body(first.get(30, TimeUnit.SECONDS)),
                    body(second.get(30, TimeUnit.SECONDS)));
        } finally {
            executor.shutdownNow();
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> body(MvcResult result) throws Exception {
        return JsonUtils.readValue(result.getResponse().getContentAsString(), Map.class);
    }

    @SuppressWarnings("unchecked")
    private static List<String> kidsOf(Map<String, Object> body) {
        assertThat(body).as("response of the jwt change").containsKey("kids");
        return (List<String>) body.get("kids");
    }

    @SuppressWarnings("unchecked")
    private static List<String> issuersOf(Map<String, Object> body) {
        assertThat(body).as("response of the jwt change").containsKey("jwt_creds");
        return ((List<Map<String, Object>>) body.get("jwt_creds")).stream().map(credential -> (String) credential.get("iss")).toList();
    }

    private List<String> storedKids(String clientId) {
        return stored(clientId).getJwkSet().getKeys().stream().map(JsonWebKey::getKid).toList();
    }

    private static String keySet(String kid) {
        return "{\"keys\":[{\"kty\":\"RSA\",\"e\":\"AQAB\",\"kid\":\"" + kid + "\",\"alg\":\"RS256\",\"n\":\"" + N + "\"}]}";
    }

    private ClientJwtConfiguration stored(String clientId) {
        return ClientJwtConfiguration.readValue(jdbcTemplate.queryForObject(
                "select client_jwt_config from oauth_client_details where client_id=? and identity_zone_id='uaa'", String.class, clientId));
    }

    // Two requests that add a key to the same client at the same time both start from the same stored configuration,
    // so the stored key set is the one written last. Both requests answer 200 and return the key ids of the client
    // after their change, so a caller can see whether its key is there and send the change again if it is not. The
    // response of the request that wrote last is the end state.
    @Test
    void concurrent_adds_of_client_jwt_keys_return_the_resulting_kids() throws Exception {
        String clientId = createClient();

        List<Map<String, Object>> responses = runBothAfterBothHaveLoaded(clientId,
                change(clientId, new ClientJwtChangeRequest(null, null, keySet("key-1"))),
                change(clientId, new ClientJwtChangeRequest(null, null, keySet("key-2"))));

        assertThat(responses).allSatisfy(response -> assertThat(kidsOf(response)).isNotEmpty().isSubsetOf("key-1", "key-2"));
        assertThat(responses).anySatisfy(response -> assertThat(kidsOf(response)).containsExactlyInAnyOrderElementsOf(storedKids(clientId)));
    }

    // The same for two federated credentials (issuer and subject): the response lists the credentials of the client
    // after the change.
    @Test
    void concurrent_adds_of_federated_client_jwt_credentials_return_the_resulting_credentials() throws Exception {
        String clientId = createClient();
        ClientJwtChangeRequest first = new ClientJwtChangeRequest();
        first.setIssuer("https://issuer-1.example.com");
        first.setSubject("subject-1");
        ClientJwtChangeRequest second = new ClientJwtChangeRequest();
        second.setIssuer("https://issuer-2.example.com");
        second.setSubject("subject-2");

        List<Map<String, Object>> responses = runBothAfterBothHaveLoaded(clientId, change(clientId, first), change(clientId, second));

        List<String> storedIssuers = stored(clientId).getClientJwtCredentials().stream().map(ClientJwtCredential::getIssuer).toList();
        assertThat(responses).allSatisfy(response -> assertThat(issuersOf(response)).isNotEmpty()
                .isSubsetOf("https://issuer-1.example.com", "https://issuer-2.example.com"));
        assertThat(responses).anySatisfy(response -> assertThat(issuersOf(response)).containsExactlyInAnyOrderElementsOf(storedIssuers));
    }

    // Guard: two changes one after the other keep both keys, and each response has the key ids after its change.
    @Test
    void sequential_adds_of_client_jwt_keys_return_the_kids_after_each_change() throws Exception {
        String clientId = createClient();

        Map<String, Object> afterFirst = body(change(clientId, new ClientJwtChangeRequest(null, null, keySet("key-1"))).call());
        Map<String, Object> afterSecond = body(change(clientId, new ClientJwtChangeRequest(null, null, keySet("key-2"))).call());

        assertThat(kidsOf(afterFirst)).containsExactly("key-1");
        assertThat(kidsOf(afterSecond)).containsExactlyInAnyOrder("key-1", "key-2");
        assertThat(storedKids(clientId)).containsExactlyInAnyOrder("key-1", "key-2");
    }
}
