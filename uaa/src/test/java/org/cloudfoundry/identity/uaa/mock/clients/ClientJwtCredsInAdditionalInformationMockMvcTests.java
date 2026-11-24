package org.cloudfoundry.identity.uaa.mock.clients;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.client.ClientJwtConfiguration;
import org.cloudfoundry.identity.uaa.client.UaaClient;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.oauth.client.ClientJwtCredential;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.MultitenantJdbcClientDetailsService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.MockMvc;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Federated credentials kept in the older form, {@code jwt_creds} in the additional information of a client, and a
 * general update of the client (PUT /oauth/clients/{id}).
 * <p>
 * Found while reviewing the response of PUT /oauth/clients/{id}/clientjwt. Not caused by that change or by the client
 * jwt hardening before it: the behavior is older (see below).
 * <p>
 * Older UAA versions kept federated credentials as {@code jwt_creds} in the additional information. They are still in
 * effect: UaaClient merges them into the configuration that client authentication uses. A general update starts from
 * the stored client as {@code getClientDetails} returns it, a ClientDetailsModification, which removes
 * {@code jwt_creds} from the additional information for the response (since commit 24adc105bb). syncWithExisting
 * therefore merges a configuration without these credentials into client_jwt_config, and then removes the older keys
 * from the additional information. The update answers 200, and the credentials are gone for every caller, with or
 * without permission to change the jwt configuration. Client authentication with them stops.
 * <p>
 * Expected: a general update that does not change the jwt configuration keeps the credentials in effect. Fails for
 * both callers. Fix: start the merge from the stored client (clientDetailsService.retrieve) instead of its response
 * form, so the credentials move into client_jwt_config as the existing merge intends; for callers that may not change
 * the jwt configuration, keep the older keys of the stored additional information as they are.
 */
@DefaultTestContext
class ClientJwtCredsInAdditionalInformationMockMvcTests {

    private static final String LEGACY_ISSUER = "https://legacy.example.com";
    private static final String STORED_ISSUER = "https://stored.example.com";

    enum Caller {
        ADMIN,
        CLIENTS_WRITE_ONLY
    }

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private TestClient testClient;
    @Autowired
    private JdbcTemplate jdbcTemplate;
    @Autowired
    private MultitenantJdbcClientDetailsService clientService;

    private String adminToken;

    @BeforeEach
    void setUp() throws Exception {
        adminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret", "uaa.admin,clients.secret");
    }

    @ParameterizedTest
    @EnumSource(Caller.class)
    void generalUpdateKeepsFederatedCredentialsInTheOlderForm(Caller caller) throws Exception {
        String clientId = createClient("jwt-legacy-" + UUID.randomUUID().toString().substring(0, 8), "uaa.none");
        storeAdditionalInformation(clientId, Map.of(ClientJwtConfiguration.JWT_CREDS,
                List.of(Map.of("iss", LEGACY_ISSUER, "sub", "legacy-subject"))));
        assertThat(issuersInEffect(clientId)).as("precondition: the credential is in effect").contains(LEGACY_ISSUER);

        generalUpdate(clientId, tokenOf(caller));

        assertThat(issuersInEffect(clientId)).contains(LEGACY_ISSUER);
    }

    // Guard, passes: a credential stored in client_jwt_config is kept by the same update.
    @ParameterizedTest
    @EnumSource(Caller.class)
    void generalUpdateKeepsFederatedCredentialsInTheClientJwtConfig(Caller caller) throws Exception {
        String clientId = createClient("jwt-stored-" + UUID.randomUUID().toString().substring(0, 8), "uaa.none");
        assertThat(jdbcTemplate.update("update oauth_client_details set client_jwt_config=? where client_id=? and identity_zone_id='uaa'",
                "{\"jwt_creds\":[{\"iss\":\"" + STORED_ISSUER + "\",\"sub\":\"stored-subject\"}]}", clientId)).isEqualTo(1);

        generalUpdate(clientId, tokenOf(caller));

        assertThat(issuersInEffect(clientId)).contains(STORED_ISSUER);
    }

    private String tokenOf(Caller caller) throws Exception {
        if (caller == Caller.ADMIN) {
            return adminToken;
        }
        String writer = createClient("clients-writer-" + UUID.randomUUID().toString().substring(0, 8), "clients.write");
        return testClient.getClientCredentialsOAuthAccessToken(writer, "secret", "clients.write");
    }

    private String createClient(String clientId, String authorities) throws Exception {
        UaaClientDetails client = new UaaClientDetails(clientId, null, "uaa.none", "client_credentials", authorities);
        client.setClientSecret("secret");
        mockMvc.perform(post("/oauth/clients")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(client)))
                .andExpect(status().isCreated());
        return clientId;
    }

    // Written as older UAA versions stored it.
    private void storeAdditionalInformation(String clientId, Map<String, Object> additionalInformation) {
        assertThat(jdbcTemplate.update("update oauth_client_details set additional_information=? where client_id=? and identity_zone_id='uaa'",
                JsonUtils.writeValueAsString(additionalInformation), clientId)).isEqualTo(1);
    }

    // A general update of another field.
    private void generalUpdate(String clientId, String token) throws Exception {
        UaaClientDetails update = new UaaClientDetails(clientId, null, "uaa.none", "client_credentials", "uaa.none");
        update.setAdditionalInformation(Map.of("name", "renamed"));
        mockMvc.perform(put("/oauth/clients/{client_id}", clientId)
                        .header("Authorization", "Bearer " + token)
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
}
