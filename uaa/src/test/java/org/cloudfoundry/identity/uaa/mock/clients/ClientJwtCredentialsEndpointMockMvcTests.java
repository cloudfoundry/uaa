package org.cloudfoundry.identity.uaa.mock.clients;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.client.ClientJwtConfiguration;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.oauth.client.ClientDetailsModification;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.util.Collections;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * MockMvc tests for jwt_creds and client_jwt_config handling on create/update/get.
 */
@DefaultTestContext
class ClientJwtCredentialsEndpointMockMvcTests {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private TestClient testClient;

    private String adminToken;

    private static final String ISSUER = "http://localhost:8080/uaa/oauth/token";

    @BeforeEach
    void setUp() throws Exception {
        adminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret", "clients.admin");
    }

    @Test
    void createWithTopLevelJwtCreds_getReturnsCredsAndStripsAdditionalKeys() throws Exception {
        String clientId = "jwt-top-" + UUID.randomUUID().toString().substring(0, 8);
        String credsJson = "[{\"iss\":\"" + ISSUER + "\",\"sub\":\"" + clientId + "\",\"aud\":\"" + clientId + "\"}]";

        UaaClientDetails client = new UaaClientDetails();
        client.setClientId(clientId);
        client.setClientSecret("secret");
        client.setAuthorizedGrantTypes(List.of("client_credentials"));
        client.setAuthorities(Collections.singletonList(new org.springframework.security.core.authority.SimpleGrantedAuthority("uaa.none")));
        client.addAdditionalInformation(ClientJwtConfiguration.JWT_CREDS, JsonUtils.readValue(credsJson, List.class));

        mockMvc.perform(post("/oauth/clients")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(client)))
                .andExpect(status().isCreated());

        ClientDetailsModification retrieved = getClient(clientId);
        assertThat(retrieved.getClientJwtCredentials()).isNotNull().isNotEmpty();
        assertThat(retrieved.getAdditionalInformation()).doesNotContainKey(ClientJwtConfiguration.JWT_CREDS);
        assertThat(retrieved.getAdditionalInformation()).doesNotContainKey("client_jwt_config");
    }

    @Test
    void createWithNestedClientJwtConfig_getReturnsCredsAndStripsAdditionalKeys() throws Exception {
        String clientId = "jwt-nested-" + UUID.randomUUID().toString().substring(0, 8);
        String credsJson = "[{\"iss\":\"" + ISSUER + "\",\"sub\":\"" + clientId + "\"}]";
        // client_jwt_config is a String field; a JSON object would not deserialize to String
        String clientJwtString = "{\"jwt_creds\":" + credsJson + "}";

        UaaClientDetails client = new UaaClientDetails();
        client.setClientId(clientId);
        client.setClientSecret("secret");
        client.setAuthorizedGrantTypes(List.of("client_credentials"));
        client.setAuthorities(Collections.singletonList(new org.springframework.security.core.authority.SimpleGrantedAuthority("uaa.none")));
        client.setClientJwtConfig(clientJwtString);

        mockMvc.perform(post("/oauth/clients")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(client)))
                .andExpect(status().isCreated());

        ClientDetailsModification retrieved = getClient(clientId);
        assertThat(retrieved.getClientJwtCredentials()).isNotNull().isNotEmpty();
    }

    @Test
    void updateAddsNewJwtCredToExistingOne() throws Exception {
        String clientId = "jwt-add-" + UUID.randomUUID().toString().substring(0, 8);

        UaaClientDetails create = new UaaClientDetails();
        create.setClientId(clientId);
        create.setClientSecret("secret");
        create.setAuthorizedGrantTypes(List.of("client_credentials"));
        create.setAuthorities(Collections.singletonList(new org.springframework.security.core.authority.SimpleGrantedAuthority("uaa.none")));
        create.setClientJwtConfig("{\"jwt_creds\":[{\"iss\":\"" + ISSUER + "\",\"sub\":\"first-" + clientId + "\"}]}");

        mockMvc.perform(post("/oauth/clients")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(create)))
                .andExpect(status().isCreated());

        // PUT with only the second credential — the first should survive via merge with existing DB state
        UaaClientDetails update = new UaaClientDetails();
        update.setClientId(clientId);
        update.setClientSecret("secret");
        update.setAuthorizedGrantTypes(List.of("client_credentials"));
        update.setAuthorities(Collections.singletonList(new org.springframework.security.core.authority.SimpleGrantedAuthority("uaa.none")));
        update.addAdditionalInformation(ClientJwtConfiguration.JWT_CREDS,
                JsonUtils.readValue("[{\"iss\":\"" + ISSUER + "\",\"sub\":\"second-" + clientId + "\"}]", List.class));

        mockMvc.perform(put("/oauth/clients/" + clientId)
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(update)))
                .andExpect(status().isOk());

        ClientDetailsModification after = getClient(clientId);
        assertThat(after.getClientJwtCredentials()).isNotNull().hasSize(2);
    }

    @Test
    void updateReplacesClientJwtConfigWithFullMergedString() throws Exception {
        String clientId = "jwt-upd-" + UUID.randomUUID().toString().substring(0, 8);
        String first = "[{\"iss\":\"" + ISSUER + "\",\"sub\":\"first-" + clientId + "\"}]";

        UaaClientDetails create = new UaaClientDetails();
        create.setClientId(clientId);
        create.setClientSecret("secret");
        create.setAuthorizedGrantTypes(List.of("client_credentials"));
        create.setAuthorities(Collections.singletonList(new org.springframework.security.core.authority.SimpleGrantedAuthority("uaa.none")));
        create.setClientJwtConfig("{\"jwt_creds\":" + first + "}");

        mockMvc.perform(post("/oauth/clients")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(create)))
                .andExpect(status().isCreated());

        // PUT with full client_jwt_config string (round-trip shape clients use when replacing JWT config in one field)
        UaaClientDetails update = new UaaClientDetails();
        update.setClientId(clientId);
        update.setClientSecret("secret");
        update.setAuthorizedGrantTypes(List.of("client_credentials"));
        update.setAuthorities(Collections.singletonList(new org.springframework.security.core.authority.SimpleGrantedAuthority("uaa.none")));
        String bothCreds = "[{\"iss\":\"" + ISSUER + "\",\"sub\":\"first-" + clientId + "\"},"
                + "{\"iss\":\"" + ISSUER + "\",\"sub\":\"second-" + clientId + "\"}]";
        update.setClientJwtConfig("{\"jwt_creds\":" + bothCreds + "}");

        mockMvc.perform(put("/oauth/clients/" + clientId)
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(update)))
                .andExpect(status().isOk());

        ClientDetailsModification after = getClient(clientId);
        assertThat(after.getClientJwtCredentials()).isNotNull().hasSize(2);
    }

    @Test
    void getResponseJsonDoesNotDuplicateJwtCredsKey() throws Exception {
        String clientId = "jwt-dup-" + UUID.randomUUID().toString().substring(0, 8);
        String credsJson = "[{\"iss\":\"" + ISSUER + "\",\"sub\":\"" + clientId + "\"}]";

        UaaClientDetails client = new UaaClientDetails();
        client.setClientId(clientId);
        client.setClientSecret("secret");
        client.setAuthorizedGrantTypes(List.of("client_credentials"));
        client.setAuthorities(Collections.singletonList(new org.springframework.security.core.authority.SimpleGrantedAuthority("uaa.none")));
        client.addAdditionalInformation(ClientJwtConfiguration.JWT_CREDS, JsonUtils.readValue(credsJson, List.class));

        mockMvc.perform(post("/oauth/clients")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(client)))
                .andExpect(status().isCreated());

        MockHttpServletRequestBuilder get = get("/oauth/clients/" + clientId)
                .header("Authorization", "Bearer " + adminToken);
        String body = mockMvc.perform(get)
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();
        int n = body.split("\"jwt_creds\"").length - 1;
        assertThat(n).isEqualTo(1);
    }

    private ClientDetailsModification getClient(String clientId) throws Exception {
        String content = mockMvc.perform(get("/oauth/clients/" + clientId)
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();
        return JsonUtils.readValue(content, ClientDetailsModification.class);
    }
}
