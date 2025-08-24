package org.cloudfoundry.identity.uaa.mock.clients;

import com.fasterxml.jackson.core.type.TypeReference;
import com.google.common.base.Strings;
import com.google.common.collect.Iterables;
import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.approval.Approval;
import org.cloudfoundry.identity.uaa.approval.Approval.ApprovalStatus;
import org.cloudfoundry.identity.uaa.approval.JdbcApprovalStore;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.audit.event.AbstractUaaEvent;
import org.cloudfoundry.identity.uaa.client.ClientMetadata;
import org.cloudfoundry.identity.uaa.client.InvalidClientDetailsException;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.client.UaaScopes;
import org.cloudfoundry.identity.uaa.client.event.ClientAdminEventPublisher;
import org.cloudfoundry.identity.uaa.client.event.ClientApprovalsDeletedEvent;
import org.cloudfoundry.identity.uaa.client.event.ClientCreateEvent;
import org.cloudfoundry.identity.uaa.client.event.ClientDeleteEvent;
import org.cloudfoundry.identity.uaa.client.event.ClientJwtChangeEvent;
import org.cloudfoundry.identity.uaa.client.event.ClientJwtFailureEvent;
import org.cloudfoundry.identity.uaa.client.event.ClientUpdateEvent;
import org.cloudfoundry.identity.uaa.client.event.SecretChangeEvent;
import org.cloudfoundry.identity.uaa.client.event.SecretFailureEvent;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.oauth.client.ClientDetailsCreation;
import org.cloudfoundry.identity.uaa.oauth.client.ClientDetailsModification;
import org.cloudfoundry.identity.uaa.oauth.client.ClientJwtChangeRequest;
import org.cloudfoundry.identity.uaa.oauth.client.SecretChangeRequest;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidClientException;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.resources.ActionResult;
import org.cloudfoundry.identity.uaa.resources.SearchResults;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.endpoints.ScimGroupEndpoints;
import org.cloudfoundry.identity.uaa.scim.endpoints.ScimUserEndpoints;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.test.ZoneSeeder;
import org.cloudfoundry.identity.uaa.test.ZoneSeederExtension;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.ClientSecretPolicy;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.util.StringUtils;
import org.springframework.web.context.WebApplicationContext;

import jakarta.servlet.http.HttpServletResponse;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.mock.util.ClientDetailsHelper.arrayFromString;
import static org.cloudfoundry.identity.uaa.mock.util.ClientDetailsHelper.clientArrayFromString;
import static org.cloudfoundry.identity.uaa.mock.util.ClientDetailsHelper.clientFromString;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.httpBearer;
import static org.cloudfoundry.identity.uaa.oauth.client.SecretChangeRequest.ChangeMode.ADD;
import static org.cloudfoundry.identity.uaa.oauth.client.SecretChangeRequest.ChangeMode.DELETE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_JWT_BEARER;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

// TODO: This class has a lot of helpers, why?
@DefaultTestContext
class ClientAdminEndpointsMockMvcTests {
    @Autowired
    private WebApplicationContext webApplicationContext;
    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private TestClient testClient;
    @Autowired
    private JdbcApprovalStore jdbcApprovalStore;
    @Autowired
    private ScimUserEndpoints scimUserEndpoints;
    @Autowired
    private ScimGroupEndpoints scimGroupEndpoints;
    @Autowired
    private ClientAdminEventPublisher eventPublisher;
    @Value("${clientMaxCount}")
    private int clientMaxCount;

    @Autowired
    @Qualifier("excludedClaims")
    LinkedHashSet excludedClaims;

    private static final String SECRET = "secret";
    private static final String TEST_PASSWORD = "password";

    private String adminUserToken;

    private ApplicationEventPublisher mockApplicationEventPublisher;
    private ApplicationEventPublisher originalApplicationEventPublisher;
    private ArgumentCaptor<AbstractUaaEvent> abstractUaaEventCaptor;
    private ScimUser testUser;
    private final RandomValueStringGenerator generator = new RandomValueStringGenerator(7);
    private static final String SECRET_TOO_LONG = Strings.repeat("a", 300);
    private List<ClientDetails> clientDetails;
    private String adminToken;
    private UaaTestAccounts testAccounts;

    @BeforeEach
    void setUp() throws Exception {
        abstractUaaEventCaptor = ArgumentCaptor.forClass(AbstractUaaEvent.class);

        originalApplicationEventPublisher = eventPublisher.getPublisher();
        mockApplicationEventPublisher = mock(ApplicationEventPublisher.class);
        eventPublisher.setApplicationEventPublisher(mockApplicationEventPublisher);

        clientDetails = new ArrayList<>();
        testAccounts = UaaTestAccounts.standard(null);
        adminToken = testClient.getClientCredentialsOAuthAccessToken(
                testAccounts.getAdminClientId(),
                testAccounts.getAdminClientSecret(),
                "clients.admin clients.read clients.write clients.secret scim.read scim.write");

        String username = new RandomValueStringGenerator().generate() + "@test.org";
        testUser = new ScimUser(null, username, "givenname", "familyname");
        testUser.setPrimaryEmail(username);
        testUser.setPassword(TEST_PASSWORD);
        testUser = MockMvcUtils.createUser(mockMvc, adminToken, testUser);
        testUser.setPassword(TEST_PASSWORD);
    }

    @AfterEach
    void teardownClients() {
        for (ClientDetails clientDetail : clientDetails) {
            delete("/oauth/clients/" + clientDetail.getClientId())
                    .header("Authorization", "Bearer" + adminUserToken)
                    .accept(APPLICATION_JSON);
        }
    }

    @AfterEach
    void restorePublisher() {
        eventPublisher.setApplicationEventPublisher(originalApplicationEventPublisher);
    }

    @Test
    void testCreateClient() throws Exception {
        ClientDetails client = createClient(adminToken, new RandomValueStringGenerator().generate(), SECRET,
                Collections.singleton("client_credentials"));
        verify(mockApplicationEventPublisher, times(1)).publishEvent(abstractUaaEventCaptor.capture());
        assertThat(abstractUaaEventCaptor.getValue().getAuditEvent().getType()).isEqualTo(AuditEventType.ClientCreateSuccess);
        assertThat(client.getAdditionalInformation()).containsEntry("name", "Client " + client.getClientId());
    }

    @Test
    void createClientWithJwtBearerGrant() throws Exception {
        String id = new RandomValueStringGenerator().generate();
        ClientDetails client = createBaseClient(id, SECRET, Collections.singletonList(GRANT_TYPE_JWT_BEARER), null, Collections.singletonList(id + ".read"));
        MockHttpServletRequestBuilder createClientPost = post("/oauth/clients")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(client));
        mockMvc.perform(createClientPost).andExpect(status().isCreated()).andReturn();
        verify(mockApplicationEventPublisher, times(1)).publishEvent(abstractUaaEventCaptor.capture());
    }

    @Test
    void createClientWithJwtBearerGrantInvalid() throws Exception {
        String id = new RandomValueStringGenerator().generate();
        ClientDetails client = createBaseClient(id, SECRET, Collections.singletonList(GRANT_TYPE_JWT_BEARER), null, null);
        MockHttpServletRequestBuilder createClientPost = post("/oauth/clients")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(client));
        MvcResult mvcResult = mockMvc.perform(createClientPost).andExpect(status().isBadRequest()).andReturn();
        assertThat(mvcResult.getResponse().getContentAsString()).contains("Scope cannot be empty for grant_type " + GRANT_TYPE_JWT_BEARER);
        verify(mockApplicationEventPublisher, times(0)).publishEvent(abstractUaaEventCaptor.capture());
    }

    @Test
    void createClientWithInvalidRedirectUrl() throws Exception {
        UaaClientDetails client = createBaseClient(new RandomValueStringGenerator().generate(), SECRET, Collections.singleton("implicit"));
        client.setRegisteredRedirectUri(Collections.singleton("*/**"));
        MockHttpServletRequestBuilder createClientPost = post("/oauth/clients")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(client));
        mockMvc.perform(createClientPost).andExpect(status().isBadRequest()).andReturn();
        verify(mockApplicationEventPublisher, times(0)).publishEvent(abstractUaaEventCaptor.capture());
    }

    @Test
    void createClientWithValidLongRedirectUri() throws Exception {
        String id = new RandomValueStringGenerator().generate();
        UaaClientDetails client = createBaseClient(id, SECRET, Collections.singletonList(GRANT_TYPE_JWT_BEARER), null, Collections.singletonList(id + ".read"));

        // redirectUri shorter than the database column size
        HashSet<String> uris = new HashSet<>();
        for (int i = 0; i < 400; ++i) {
            uris.add("http://example.com/myuri/foo/bar/abcdefg/abcdefg" + i);
        }
        client.setRegisteredRedirectUri(uris);

        MockHttpServletRequestBuilder createClientPost = post("/oauth/clients")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(client));
        mockMvc.perform(createClientPost).andExpect(status().isCreated()).andReturn();
        verify(mockApplicationEventPublisher, times(1)).publishEvent(abstractUaaEventCaptor.capture());
    }

    // TODO: put in a nested context to clean up the excluded claims
    @Test
    void createClient_withClientAdminToken_withAuthoritiesExcluded() throws Exception {
        String clientId = generator.generate().toLowerCase();
        excludedClaims.add("authorities");
        try {
            String clientAdminToken = testClient.getClientCredentialsOAuthAccessToken(
                    testAccounts.getAdminClientId(),
                    testAccounts.getAdminClientSecret(),
                    "clients.admin");
            List<String> authorities = Arrays.asList("password.write", "scim.write", "scim.read");
            List<String> scopes = Arrays.asList("foo", "bar", "oauth.approvals");
            ClientDetailsModification client = createBaseClient(clientId, SECRET, Collections.singleton("client_credentials"), authorities, scopes);
            MockHttpServletRequestBuilder createClientPost = post("/oauth/clients")
                    .header("Authorization", "Bearer " + clientAdminToken)
                    .accept(APPLICATION_JSON)
                    .contentType(APPLICATION_JSON)
                    .content(JsonUtils.writeValueAsString(client));
            ResultActions createResult = mockMvc.perform(createClientPost).andExpect(status().isCreated());
            UaaClientDetails clientDetails = JsonUtils.readValue(createResult.andReturn().getResponse().getContentAsString(), UaaClientDetails.class);
            MockHttpServletRequestBuilder getClientMetadata = get("/oauth/clients/" + clientDetails.getClientId() + "/meta")
                    .header("Authorization", "Bearer " + clientAdminToken)
                    .accept(APPLICATION_JSON)
                    .contentType(APPLICATION_JSON);
            ResultActions getResult = mockMvc.perform(getClientMetadata).andExpect(status().isOk());
            JsonUtils.readValue(getResult.andReturn().getResponse().getContentAsString(), ClientMetadata.class);
        } finally {
            excludedClaims.remove("authorities");
        }
    }

    @Test
    void createClientWithLongSecret() throws Exception {
        UaaClientDetails client = createBaseClient(new RandomValueStringGenerator().generate(), SECRET_TOO_LONG, Collections.singleton("client_credentials"));
        MockHttpServletRequestBuilder createClientPost = post("/oauth/clients")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(client));
        mockMvc.perform(createClientPost).andExpect(status().isBadRequest());
        getClient(client.getClientId());
        verifyNoMoreInteractions(mockApplicationEventPublisher);
    }

    @Test
    void createClientWithSecondarySecret() throws Exception {
        var client = new ClientDetailsCreation();
        client.setClientId(new RandomValueStringGenerator().generate());
        client.setClientSecret("primarySecret");
        client.setSecondaryClientSecret("secondarySecret");
        client.setAuthorizedGrantTypes(List.of("client_credentials"));

        MockHttpServletRequestBuilder createClientPost = post("/oauth/clients")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(client));

        mockMvc.perform(createClientPost)
                .andExpect(status().isCreated());

        getClient(client.getClientId());
        verify(mockApplicationEventPublisher).publishEvent(abstractUaaEventCaptor.capture());
        assertThat(abstractUaaEventCaptor.getValue().getAuditEvent().getType()).isEqualTo(AuditEventType.ClientCreateSuccess);
    }

    @Test
    void clientCRUDAsAdminUser() throws Exception {
        setupAdminUserToken();
        ClientDetails client = createClient(adminUserToken, SECRET, new RandomValueStringGenerator().generate(),
                Collections.singleton("client_credentials"));
        verify(mockApplicationEventPublisher, times(2)).publishEvent(abstractUaaEventCaptor.capture());
        for (AbstractUaaEvent event : abstractUaaEventCaptor.getAllValues()) {
            assertThat(event.getAuditEvent().getType()).isEqualTo(AuditEventType.ClientCreateSuccess);
        }

        MockHttpServletRequestBuilder getClient = get("/oauth/clients/" + client.getClientId())
                .header("Authorization", "Bearer " + adminUserToken)
                .accept(APPLICATION_JSON);
        MvcResult mvcResult = mockMvc.perform(getClient)
                .andExpect(status().isOk())
                .andReturn();
        UaaClientDetails clientDetails = JsonUtils.readValue(mvcResult.getResponse().getContentAsString(), UaaClientDetails.class);
        assertThat(clientDetails.getClientId()).isEqualTo(client.getClientId());

        clientDetails.setAuthorizedGrantTypes(Collections.singleton(GRANT_TYPE_AUTHORIZATION_CODE));
        MockHttpServletRequestBuilder updateClient = put("/oauth/clients/" + client.getClientId())
                .header("Authorization", "Bearer" + adminUserToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(clientDetails));
        MvcResult result = mockMvc.perform(updateClient).andExpect(status().isOk()).andReturn();
        UaaClientDetails updatedClientDetails = JsonUtils.readValue(result.getResponse().getContentAsString(), UaaClientDetails.class);
        assertThat(updatedClientDetails.getClientId()).isEqualTo(client.getClientId());
        assertThat(updatedClientDetails.getAuthorizedGrantTypes()).contains(GRANT_TYPE_AUTHORIZATION_CODE);

        MockHttpServletRequestBuilder deleteClient = delete("/oauth/clients/" + client.getClientId())
                .header("Authorization", "Bearer" + adminUserToken)
                .accept(APPLICATION_JSON);
        MvcResult deleteResult = mockMvc.perform(deleteClient).andExpect(status().isOk()).andReturn();
        UaaClientDetails deletedClientDetails = JsonUtils.readValue(deleteResult.getResponse().getContentAsString(), UaaClientDetails.class);
        assertThat(deletedClientDetails.getClientId()).isEqualTo(client.getClientId());
    }

    @Test
    void create_client_and_check_created_by() throws Exception {
        setupAdminUserToken();

        UaaClientDetails clientDetails = createClient(Arrays.asList("password.write", "scim.write", "scim.read", "clients.write"));

        ClientMetadata clientMetadata = obtainClientMetadata(clientDetails.getClientId());
        SearchResults<Map<String, Object>> marissa = (SearchResults<Map<String, Object>>) scimUserEndpoints.findUsers("id,userName", "userName eq \"" + testUser.getUserName() + "\"", "userName", "asc", 0, 1);
        String marissaId = (String) marissa.getResources().getFirst().get("id");
        assertThat(clientMetadata.getCreatedBy()).isEqualTo(marissaId);

        clientDetails = createClient(Collections.singletonList("uaa.resource"));

        clientMetadata = obtainClientMetadata(clientDetails.getClientId());
        assertThat(clientMetadata.getCreatedBy()).isEqualTo(marissaId);
    }

    @Test
    void read_restricted_scopes() throws Exception {
        MockHttpServletRequestBuilder createClientPost = get("/oauth/clients/restricted")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON);
        mockMvc.perform(createClientPost)
                .andExpect(status().isOk())
                .andExpect(content().string(JsonUtils.writeValueAsString(new UaaScopes().getUaaScopes())));
    }

    @Test
    void createRestrictedClientFails() throws Exception {
        String id = new RandomValueStringGenerator().generate();
        List<String> grantTypes = Arrays.asList("client_credentials", "password");
        UaaClientDetails clientWithAuthorities = createBaseClient(id, SECRET, grantTypes, new UaaScopes().getUaaScopes(), null);
        UaaClientDetails clientWithScopes = createBaseClient(id, SECRET, grantTypes, null, new UaaScopes().getUaaScopes());

        MockHttpServletRequestBuilder createClientPost = post("/oauth/clients/restricted")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(clientWithAuthorities));
        mockMvc.perform(createClientPost).andExpect(status().isBadRequest());

        createClientPost = post("/oauth/clients/restricted")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(clientWithScopes));
        mockMvc.perform(createClientPost).andExpect(status().isBadRequest());
    }

    @Test
    void createRestrictedClientSucceeds() throws Exception {
        String id = new RandomValueStringGenerator().generate();
        List<String> scopes = Collections.singletonList("openid");
        UaaClientDetails client = createBaseClient(id, SECRET, Arrays.asList("client_credentials", "password"), scopes, scopes);

        MockHttpServletRequestBuilder createClientPost = post("/oauth/clients/restricted")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(client));
        mockMvc.perform(createClientPost).andExpect(status().isCreated());

        createClientPost = put("/oauth/clients/restricted/" + id)
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(client));
        mockMvc.perform(createClientPost).andExpect(status().isOk());

        client.setScope(new UaaScopes().getUaaScopes());
        createClientPost = put("/oauth/clients/restricted/" + id)
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(client));
        mockMvc.perform(createClientPost).andExpect(status().isBadRequest());
    }

    @Test
    void createClientsTxFailureSecretTooLong() throws Exception {
        int count = 5;
        UaaClientDetails[] details = createBaseClients(count, SECRET_TOO_LONG, null);
        MockHttpServletRequestBuilder createClientPost = post("/oauth/clients/tx")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(details));
        ResultActions result = mockMvc.perform(createClientPost);
        result.andExpect(status().isBadRequest());
        verifyNoMoreInteractions(mockApplicationEventPublisher);
    }

    @Test
    void createClientsTxSuccess() throws Exception {
        int count = 5;
        UaaClientDetails[] details = createBaseClients(count, SECRET, null);
        MockHttpServletRequestBuilder createClientPost = post("/oauth/clients/tx")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(details));
        ResultActions result = mockMvc.perform(createClientPost);
        result.andExpect(status().isCreated());
        ClientDetails[] clients = clientArrayFromString(result.andReturn().getResponse().getContentAsString());
        for (ClientDetails client : clients) {
            ClientDetails c = getClient(client.getClientId());
            assertThat(c).isNotNull();
            assertThat(c.getClientSecret()).isNull();
        }
        verify(mockApplicationEventPublisher, times(count)).publishEvent(abstractUaaEventCaptor.capture());
        for (AbstractUaaEvent event : abstractUaaEventCaptor.getAllValues()) {
            assertThat(event.getAuditEvent().getType()).isEqualTo(AuditEventType.ClientCreateSuccess);
        }
    }

    @Test
    void createClientsTxDuplicateId() throws Exception {
        UaaClientDetails[] details = createBaseClients(5, SECRET, null);
        details[details.length - 1] = details[0];
        MockHttpServletRequestBuilder createClientPost = post("/oauth/clients/tx")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(details));
        mockMvc.perform(createClientPost).andExpect(status().isConflict());
        for (ClientDetails client : details) {
            assertThat(getClient(client.getClientId())).isNull();
        }
        verify(mockApplicationEventPublisher, times(0)).publishEvent(abstractUaaEventCaptor.capture());
    }

    @Test
    void in_zone_client_write_failure_with_min_length_secret() throws Exception {
        String subdomain = generator.generate();
        MockMvcUtils.IdentityZoneCreationResult result = MockMvcUtils.createOtherIdentityZoneAndReturnResult(subdomain, mockMvc, webApplicationContext, null, IdentityZoneHolder.getCurrentZoneId());
        result.getIdentityZone().getConfig().setClientSecretPolicy(new ClientSecretPolicy(7, 255, 0, 0, 0, 0, 6));
        MockMvcUtils.setZoneConfiguration(webApplicationContext, result.getIdentityZone().getId(), result.getIdentityZone().getConfig());

        String clientId = generator.generate();
        UaaClientDetails client = new UaaClientDetails(clientId, "", "openid", GRANT_TYPE_AUTHORIZATION_CODE, "", "http://sample.redirect");
        client.setClientSecret("secret");
        MockMvcUtils.createClient(mockMvc, result.getZoneAdminToken(), client, result.getIdentityZone(), status().isBadRequest());
    }

    @Test
    void in_zone_client_write_failure_with_secret_too_long() throws Exception {
        String subdomain = generator.generate();
        MockMvcUtils.IdentityZoneCreationResult result = MockMvcUtils.createOtherIdentityZoneAndReturnResult(subdomain, mockMvc, webApplicationContext, null, IdentityZoneHolder.getCurrentZoneId());
        result.getIdentityZone().getConfig().setClientSecretPolicy(new ClientSecretPolicy(0, 5, 0, 0, 0, 0, 6));
        MockMvcUtils.setZoneConfiguration(webApplicationContext, result.getIdentityZone().getId(), result.getIdentityZone().getConfig());

        String clientId = generator.generate();
        UaaClientDetails client = new UaaClientDetails(clientId, "", "openid", GRANT_TYPE_AUTHORIZATION_CODE, "", "http://sample.redirect");
        client.setClientSecret("secret");
        MockMvcUtils.createClient(mockMvc, result.getZoneAdminToken(), client, result.getIdentityZone(), status().isBadRequest());
    }

    @Test
    void in_zone_client_write_failure_with_secret_requires_uppercase_character() throws Exception {
        String subdomain = generator.generate();
        MockMvcUtils.IdentityZoneCreationResult result = MockMvcUtils.createOtherIdentityZoneAndReturnResult(subdomain, mockMvc, webApplicationContext, null, IdentityZoneHolder.getCurrentZoneId());
        result.getIdentityZone().getConfig().setClientSecretPolicy(new ClientSecretPolicy(0, 255, 1, 0, 0, 0, 6));
        MockMvcUtils.setZoneConfiguration(webApplicationContext, result.getIdentityZone().getId(), result.getIdentityZone().getConfig());

        String clientId = generator.generate();
        UaaClientDetails client = new UaaClientDetails(clientId, "", "openid", GRANT_TYPE_AUTHORIZATION_CODE, "", "http://sample.redirect");
        client.setClientSecret("secret");
        MockMvcUtils.createClient(mockMvc, result.getZoneAdminToken(), client, result.getIdentityZone(), status().isBadRequest());
    }

    @Test
    void in_zone_client_write_failure_with_secret_requires_lowercase_character() throws Exception {
        String subdomain = generator.generate();
        MockMvcUtils.IdentityZoneCreationResult result = MockMvcUtils.createOtherIdentityZoneAndReturnResult(subdomain, mockMvc, webApplicationContext, null, IdentityZoneHolder.getCurrentZoneId());
        result.getIdentityZone().getConfig().setClientSecretPolicy(new ClientSecretPolicy(0, 255, 0, 1, 0, 0, 6));
        MockMvcUtils.setZoneConfiguration(webApplicationContext, result.getIdentityZone().getId(), result.getIdentityZone().getConfig());

        String clientId = generator.generate();
        UaaClientDetails client = new UaaClientDetails(clientId, "", "openid", GRANT_TYPE_AUTHORIZATION_CODE, "", "http://sample.redirect");
        client.setClientSecret("SECRET");
        MockMvcUtils.createClient(mockMvc, result.getZoneAdminToken(), client, result.getIdentityZone(), status().isBadRequest());
    }

    @Test
    void in_zone_client_write_success_with_complex_secret_policy() throws Exception {
        String subdomain = generator.generate();
        MockMvcUtils.IdentityZoneCreationResult result = MockMvcUtils.createOtherIdentityZoneAndReturnResult(subdomain, mockMvc, webApplicationContext, null, IdentityZoneHolder.getCurrentZoneId());
        result.getIdentityZone().getConfig().setClientSecretPolicy(new ClientSecretPolicy(6, 255, 1, 1, 1, 1, 6));
        MockMvcUtils.setZoneConfiguration(webApplicationContext, result.getIdentityZone().getId(), result.getIdentityZone().getConfig());

        String clientId = generator.generate();
        UaaClientDetails client = new UaaClientDetails(clientId, "", "openid", GRANT_TYPE_AUTHORIZATION_CODE, "", "http://sample.redirect");
        client.setClientSecret("Secret1@");
        MockMvcUtils.createClient(mockMvc, result.getZoneAdminToken(), client, result.getIdentityZone(), status().isCreated());
    }

    @Test
    void in_zone_client_write_failure_with_secret_requires_special_character() throws Exception {
        String subdomain = generator.generate();
        MockMvcUtils.IdentityZoneCreationResult result = MockMvcUtils.createOtherIdentityZoneAndReturnResult(subdomain, mockMvc, webApplicationContext, null, IdentityZoneHolder.getCurrentZoneId());
        result.getIdentityZone().getConfig().setClientSecretPolicy(new ClientSecretPolicy(0, 255, 0, 0, 0, 1, 6));
        MockMvcUtils.setZoneConfiguration(webApplicationContext, result.getIdentityZone().getId(), result.getIdentityZone().getConfig());

        String clientId = generator.generate();
        UaaClientDetails client = new UaaClientDetails(clientId, "", "openid", GRANT_TYPE_AUTHORIZATION_CODE, "", "http://sample.redirect");
        client.setClientSecret("secret");
        MockMvcUtils.createClient(mockMvc, result.getZoneAdminToken(), client, result.getIdentityZone(), status().isBadRequest());
    }

    @Test
    void in_zone_client_write_failure_with_secret_requires_digit() throws Exception {
        String subdomain = generator.generate();
        MockMvcUtils.IdentityZoneCreationResult result = MockMvcUtils.createOtherIdentityZoneAndReturnResult(subdomain, mockMvc, webApplicationContext, null, IdentityZoneHolder.getCurrentZoneId());
        result.getIdentityZone().getConfig().setClientSecretPolicy(new ClientSecretPolicy(0, 255, 0, 0, 1, 0, 6));
        MockMvcUtils.setZoneConfiguration(webApplicationContext, result.getIdentityZone().getId(), result.getIdentityZone().getConfig());

        String clientId = generator.generate();
        UaaClientDetails client = new UaaClientDetails(clientId, "", "openid", GRANT_TYPE_AUTHORIZATION_CODE, "", "http://sample.redirect");
        client.setClientSecret("secret");
        MockMvcUtils.createClient(mockMvc, result.getZoneAdminToken(), client, result.getIdentityZone(), status().isBadRequest());
    }

    @Test
    void in_zone_client_write_using_zones_dot_admin() throws Exception {
        String subdomain = generator.generate();
        MockMvcUtils.IdentityZoneCreationResult result = MockMvcUtils.createOtherIdentityZoneAndReturnResult(subdomain, mockMvc, webApplicationContext, null, IdentityZoneHolder.getCurrentZoneId());
        String clientId = generator.generate();
        UaaClientDetails client = new UaaClientDetails(clientId, "", "openid", GRANT_TYPE_AUTHORIZATION_CODE, "", "http://some.redirect.url.com");
        client.setClientSecret("secret");
        MockMvcUtils.createClient(mockMvc, result.getZoneAdminToken(), client, result.getIdentityZone(), status().isCreated());
    }

    @Test
    void in_zone_client_write_using_zones_dot_clients_dot_admin() throws Exception {
        String subdomain = generator.generate();
        MockMvcUtils.IdentityZoneCreationResult result = MockMvcUtils.createOtherIdentityZoneAndReturnResult(subdomain, mockMvc, webApplicationContext, null, IdentityZoneHolder.getCurrentZoneId());
        String id = result.getIdentityZone().getId();
        String clientId = generator.generate();
        UaaClientDetails client = new UaaClientDetails(clientId, "", "", "client_credentials", "zones." + id + ".clients.admin", "http://some.redirect.url.com");
        client.setClientSecret("secret");
        client = MockMvcUtils.createClient(mockMvc, adminToken, client);
        client.setClientSecret("secret");

        String zonesClientsAdminToken = MockMvcUtils.getClientOAuthAccessToken(mockMvc, client.getClientId(), client.getClientSecret(), "zones." + id + ".clients.admin");

        UaaClientDetails newclient = new UaaClientDetails(clientId, "", "openid", GRANT_TYPE_AUTHORIZATION_CODE, "", "http://some.redirect.url.com");
        newclient.setClientSecret("secret");
        newclient = MockMvcUtils.createClient(mockMvc, zonesClientsAdminToken, newclient,
                result.getIdentityZone(), status().isCreated());

        MockMvcUtils.updateClient(mockMvc, zonesClientsAdminToken, newclient, result.getIdentityZone());
    }

    @Test
    void manageClientInOtherZone_Using_AdminUserTokenFromDefaultZone() throws Exception {
        String subdomain = generator.generate();
        MockMvcUtils.IdentityZoneCreationResult result = MockMvcUtils.createOtherIdentityZoneAndReturnResult(subdomain, mockMvc, webApplicationContext, null, IdentityZoneHolder.getCurrentZoneId());
        String zoneId = result.getIdentityZone().getId();
        String clientId = generator.generate();

        setupAdminUserToken();

        UaaClientDetails client = new UaaClientDetails(clientId, "", "openid", GRANT_TYPE_AUTHORIZATION_CODE, "", "http://some.redirect.url.com");
        client.setClientSecret("secret");
        UaaClientDetails createdClient = MockMvcUtils.createClient(mockMvc, adminUserToken, client,
                result.getIdentityZone(), status().isCreated());

        assertThat(createdClient.getClientId()).isEqualTo(client.getClientId());

        MockHttpServletRequestBuilder getClient = get("/oauth/clients/" + client.getClientId())
                .header("Authorization", "Bearer " + adminUserToken)
                .header("X-Identity-Zone-Id", zoneId)
                .accept(APPLICATION_JSON);
        MvcResult mvcResult = mockMvc.perform(getClient)
                .andExpect(status().isOk())
                .andReturn();
        UaaClientDetails clientDetails = JsonUtils.readValue(mvcResult.getResponse().getContentAsString(), UaaClientDetails.class);
        assertThat(clientDetails.getClientId()).isEqualTo(client.getClientId());

        clientDetails.setAuthorizedGrantTypes(Collections.singleton(GRANT_TYPE_AUTHORIZATION_CODE));
        MockHttpServletRequestBuilder updateClient = put("/oauth/clients/" + client.getClientId())
                .header("Authorization", "Bearer" + adminUserToken)
                .header("X-Identity-Zone-Id", zoneId)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(clientDetails));
        mvcResult = mockMvc.perform(updateClient).andExpect(status().isOk()).andReturn();
        UaaClientDetails updatedClientDetails = JsonUtils.readValue(mvcResult.getResponse().getContentAsString(), UaaClientDetails.class);
        assertThat(updatedClientDetails.getClientId()).isEqualTo(client.getClientId());
        assertThat(updatedClientDetails.getAuthorizedGrantTypes()).contains(GRANT_TYPE_AUTHORIZATION_CODE);

        MockHttpServletRequestBuilder deleteClient = delete("/oauth/clients/" + client.getClientId())
                .header("Authorization", "Bearer" + adminUserToken)
                .header("X-Identity-Zone-Id", zoneId)
                .accept(APPLICATION_JSON);
        MvcResult deleteResult = mockMvc.perform(deleteClient).andExpect(status().isOk()).andReturn();
        UaaClientDetails deletedClientDetails = JsonUtils.readValue(deleteResult.getResponse().getContentAsString(), UaaClientDetails.class);
        assertThat(deletedClientDetails.getClientId()).isEqualTo(client.getClientId());
    }

    @Test
    void in_zone_client_read_using_zones_dot_clients_dot_admin() throws Exception {
        String subdomain = generator.generate();
        MockMvcUtils.IdentityZoneCreationResult result = MockMvcUtils.createOtherIdentityZoneAndReturnResult(subdomain, mockMvc, webApplicationContext, null, IdentityZoneHolder.getCurrentZoneId());
        String id = result.getIdentityZone().getId();
        String clientId = generator.generate();
        UaaClientDetails client = new UaaClientDetails(clientId, "", "", "client_credentials", "zones." + id + ".clients.admin", "http://some.redirect.url.com");
        client.setClientSecret("secret");
        client = MockMvcUtils.createClient(mockMvc, adminToken, client);
        client.setClientSecret("secret");

        String zonesClientsAdminToken = MockMvcUtils.getClientOAuthAccessToken(mockMvc, client.getClientId(), client.getClientSecret(), "zones." + id + ".clients.admin");

        UaaClientDetails newclient = new UaaClientDetails(clientId, "", "openid", GRANT_TYPE_AUTHORIZATION_CODE, "", "http://some.redirect.url.com");
        newclient.setClientSecret("secret");
        MockMvcUtils.createClient(mockMvc, zonesClientsAdminToken, newclient, result.getIdentityZone(), status().isCreated());
    }

    @Test
    void in_zone_client_read_using_zones_dot_clients_dot_read() throws Exception {
        String subdomain = generator.generate();
        MockMvcUtils.IdentityZoneCreationResult result = MockMvcUtils.createOtherIdentityZoneAndReturnResult(subdomain, mockMvc, webApplicationContext, null, IdentityZoneHolder.getCurrentZoneId());
        String id = result.getIdentityZone().getId();
        String clientId = generator.generate();
        UaaClientDetails client = new UaaClientDetails(clientId, "", "", "client_credentials", "zones." + id + ".clients.read", "http://some.redirect.url.com");
        client.setClientSecret("secret");
        client = MockMvcUtils.createClient(mockMvc, adminToken, client);
        client.setClientSecret("secret");

        String zonesClientsReadToken = MockMvcUtils.getClientOAuthAccessToken(mockMvc, client.getClientId(), client.getClientSecret(), "zones." + id + ".clients.read");

        UaaClientDetails newclient = new UaaClientDetails(clientId, "", "openid", GRANT_TYPE_AUTHORIZATION_CODE, "", "http://some.redirect.url.com");
        newclient.setClientSecret("secret");
        MockMvcUtils.createClient(mockMvc, result.getZoneAdminToken(), newclient, result.getIdentityZone(), status().isCreated());

        MockMvcUtils.getClient(mockMvc, zonesClientsReadToken, newclient.getClientId(), result.getIdentityZone());
    }

    @Test
    void createClientsTxClientCredentialsWithoutSecret() throws Exception {
        UaaClientDetails[] details = createBaseClients(5, null, null);
        details[details.length - 1].setAuthorizedGrantTypes(StringUtils.commaDelimitedListToSet("client_credentials"));
        details[details.length - 1].setClientSecret(null);
        MockHttpServletRequestBuilder createClientPost = post("/oauth/clients/tx")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(details));
        mockMvc.perform(createClientPost).andExpect(status().isCreated());
        for (ClientDetails client : details) {
            assertThat(getClient(client.getClientId())).isNotNull();
        }
        verify(mockApplicationEventPublisher, atLeast(5)).publishEvent(abstractUaaEventCaptor.capture());
    }

    @Test
    void updateClientsTxSuccess() throws Exception {
        int count = 5;
        UaaClientDetails[] details = new UaaClientDetails[count];
        for (int i = 0; i < details.length; i++) {
            details[i] = (UaaClientDetails) createClient(adminToken, null, SECRET, null);
            details[i].setRefreshTokenValiditySeconds(120);
        }
        MockHttpServletRequestBuilder updateClientPut = put("/oauth/clients/tx")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(details));
        ResultActions result = mockMvc.perform(updateClientPut);
        result.andExpect(status().isOk());
        ClientDetails[] clients = clientArrayFromString(result.andReturn().getResponse().getContentAsString());
        for (ClientDetails client : clients) {
            assertThat(getClient(client.getClientId())).isNotNull();
            assertThat(client.getRefreshTokenValiditySeconds()).isEqualTo(Integer.valueOf(120));
        }
        //create and then update events
        verify(mockApplicationEventPublisher, times(count * 2)).publishEvent(abstractUaaEventCaptor.capture());
        int index = 0;
        for (AbstractUaaEvent event : abstractUaaEventCaptor.getAllValues()) {
            if (index < count) {
                assertThat(event.getAuditEvent().getType()).isEqualTo(AuditEventType.ClientCreateSuccess);
            } else {
                assertThat(event.getAuditEvent().getType()).isEqualTo(AuditEventType.ClientUpdateSuccess);
            }
            index++;
        }
    }

    @Test
    void updateClientsTxInvalidId() throws Exception {
        int count = 5;
        UaaClientDetails[] details = new UaaClientDetails[count];
        for (int i = 0; i < details.length; i++) {
            details[i] = (UaaClientDetails) createClient(adminToken, null, SECRET, null);
            details[i].setRefreshTokenValiditySeconds(120);
        }
        String firstId = details[0].getClientId();
        details[0].setClientId("unknown.client.id");

        MockHttpServletRequestBuilder updateClientPut = put("/oauth/clients/tx")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(details));
        ResultActions result = mockMvc.perform(updateClientPut);
        result.andExpect(status().isNotFound());
        details[0].setClientId(firstId);
        for (ClientDetails client : details) {
            ClientDetails c = getClient(client.getClientId());
            assertThat(c).isNotNull();
            assertThat(c.getClientSecret()).isNull();
            assertThat(c.getRefreshTokenValiditySeconds()).isNull();
        }
        //create and then update events
        verify(mockApplicationEventPublisher, times(count)).publishEvent(abstractUaaEventCaptor.capture());
    }

    @Test
    void deleteClientsTxSuccess() throws Exception {
        int count = 5;
        UaaClientDetails[] details = new UaaClientDetails[count];
        for (int i = 0; i < details.length; i++) {
            details[i] = (UaaClientDetails) createClient(adminToken, null, SECRET, null);
        }
        MockHttpServletRequestBuilder deleteClientsPost = post("/oauth/clients/tx/delete")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(details));
        ResultActions result = mockMvc.perform(deleteClientsPost);
        result.andExpect(status().isOk());
        for (ClientDetails client : details) {
            assertThat(getClient(client.getClientId())).isNull();
        }
        //create and then update events
        verify(mockApplicationEventPublisher, times(count * 2)).publishEvent(abstractUaaEventCaptor.capture());
        int index = 0;
        for (AbstractUaaEvent event : abstractUaaEventCaptor.getAllValues()) {
            if (index < count) {
                assertThat(event.getAuditEvent().getType()).isEqualTo(AuditEventType.ClientCreateSuccess);
            } else {
                assertThat(event.getAuditEvent().getType()).isEqualTo(AuditEventType.ClientDeleteSuccess);
            }
            index++;
        }
    }

    @Test
    void deleteClientsTxRollbackInvalidId() throws Exception {
        int count = 5;
        UaaClientDetails[] details = new UaaClientDetails[count];
        for (int i = 0; i < details.length; i++) {
            details[i] = (UaaClientDetails) createClient(adminToken, null, SECRET, null);
        }
        String firstId = details[0].getClientId();
        details[0].setClientId("unknown.client.id");

        MockHttpServletRequestBuilder deleteClientsPost = post("/oauth/clients/tx/delete")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(details));
        ResultActions result = mockMvc.perform(deleteClientsPost);
        result.andExpect(status().isNotFound());
        details[0].setClientId(firstId);
        for (ClientDetails client : details) {
            ClientDetails c = getClient(client.getClientId());
            assertThat(c).isNotNull();
            assertThat(c.getClientSecret()).isNull();
            assertThat(c.getRefreshTokenValiditySeconds()).isNull();
        }
        verify(mockApplicationEventPublisher, times(count)).publishEvent(abstractUaaEventCaptor.capture());
    }

    @Test
    void addUpdateDeleteClientsTxSuccess() throws Exception {
        int count = 5;
        ClientDetailsModification[] details = new ClientDetailsModification[count * 3];
        for (int i = 0; i < count; i++) {
            details[i] = (ClientDetailsModification) createClient(adminToken, null, SECRET, null);
            details[i].setRefreshTokenValiditySeconds(120);
            details[i].setAction(ClientDetailsModification.UPDATE);
        }
        for (int i = count; i < (count * 2); i++) {
            details[i] = (ClientDetailsModification) createClient(adminToken, null, SECRET, null);
            details[i].setAction(ClientDetailsModification.DELETE);
        }
        for (int i = count * 2; i < (count * 3); i++) {
            details[i] = createBaseClient(null, SECRET, null);
            details[i].setAction(ClientDetailsModification.ADD);
        }

        MockHttpServletRequestBuilder modifyClientsPost = post("/oauth/clients/tx/modify")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(details));
        ResultActions result = mockMvc.perform(modifyClientsPost);
        result.andExpect(status().isOk());

        for (int i = 0; i < count; i++) {
            ClientDetails c = getClient(details[i].getClientId());
            assertThat(c).isNotNull();
            assertThat(c.getRefreshTokenValiditySeconds()).isEqualTo(Integer.valueOf(120));

        }
        for (int i = count; i < (count * 2); i++) {
            ClientDetails c = getClient(details[i].getClientId());
            assertThat(c).isNull();
        }
        for (int i = count * 2; i < (count * 3); i++) {
            ClientDetails c = getClient(details[i].getClientId());
            assertThat(c).isNotNull();
            assertThat(c.getRefreshTokenValiditySeconds()).isNull();
        }
        verify(mockApplicationEventPublisher, times(count * 5)).publishEvent(abstractUaaEventCaptor.capture());
        int index = 0;
        for (AbstractUaaEvent event : abstractUaaEventCaptor.getAllValues()) {
            int swit = index / count;
            switch (swit) {
                case 0, 1, 4: {
                    //1-10 and 21-25 events are create
                    assertThat(event.getAuditEvent().getType()).isEqualTo(AuditEventType.ClientCreateSuccess);
                    assertThat(event.getClass()).isEqualTo(ClientCreateEvent.class);
                    assertThat(event.getAuditEvent().getPrincipalId()).isEqualTo(details[index < 10 ? index : (index - count * 2)].getClientId());
                    break;
                }
                case 2: {
                    //the 11-15 events are update
                    assertThat(event.getAuditEvent().getType()).isEqualTo(AuditEventType.ClientUpdateSuccess);
                    assertThat(event.getClass()).isEqualTo(ClientUpdateEvent.class);
                    assertThat(event.getAuditEvent().getPrincipalId()).isEqualTo(details[index - (count * 2)].getClientId());
                    break;
                }
                case 3: {
                    //the 16-20 events are deletes
                    assertThat(event.getAuditEvent().getType()).isEqualTo(AuditEventType.ClientDeleteSuccess);
                    assertThat(event.getClass()).isEqualTo(ClientDeleteEvent.class);
                    assertThat(event.getAuditEvent().getPrincipalId()).isEqualTo(details[index - count * 2].getClientId());
                    break;
                }
            }
            index++;
        }
    }

    @Test
    void addUpdateDeleteClientsTxDeleteUnsuccessfulRollback() throws Exception {
        ClientDetailsModification[] details = new ClientDetailsModification[15];
        for (int i = 0; i < 5; i++) {
            details[i] = (ClientDetailsModification) createClient(adminToken, null, SECRET,
                    Collections.singleton("password"));
            details[i].setRefreshTokenValiditySeconds(120);
            details[i].setAction(ClientDetailsModification.UPDATE);
        }
        for (int i = 5; i < 10; i++) {
            details[i] = (ClientDetailsModification) createClient(adminToken, null, SECRET, null);
            details[i].setAction(ClientDetailsModification.DELETE);
        }
        for (int i = 10; i < 15; i++) {
            details[i] = createBaseClient(null, null, null);
            details[i].setAction(ClientDetailsModification.ADD);
        }

        String userToken = testClient.getUserOAuthAccessToken(
                details[0].getClientId(),
                "secret",
                testUser.getUserName(),
                TEST_PASSWORD,
                "oauth.approvals");
        addApprovals(userToken, details[0].getClientId());
        Approval[] approvals = getApprovals(details[0].getClientId());
        assertThat(approvals).hasSize(3);

        String deleteId = details[5].getClientId();
        details[5].setClientId("unknown.client.id");

        MockHttpServletRequestBuilder modifyClientsPost = post("/oauth/clients/tx/modify")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(details));
        ResultActions result = mockMvc.perform(modifyClientsPost);
        result.andExpect(status().isNotFound());
        details[5].setClientId(deleteId);

        for (int i = 0; i < 5; i++) {
            ClientDetails c = getClient(details[i].getClientId());
            assertThat(c).isNotNull();
            assertThat(c.getRefreshTokenValiditySeconds()).isNull();

        }
        for (int i = 5; i < 10; i++) {
            ClientDetails c = getClient(details[i].getClientId());
            assertThat(c).isNotNull();
        }
        for (int i = 10; i < 15; i++) {
            ClientDetails c = getClient(details[i].getClientId());
            assertThat(c).isNull();
        }
        approvals = getApprovals(details[0].getClientId());
        assertThat(approvals).hasSize(3);
    }

    @Test
    void approvalsAreDeleted() throws Exception {
        ClientDetails details = createClient(adminToken, new RandomValueStringGenerator().generate(),
                SECRET, Collections.singleton("password"));
        String userToken = testClient.getUserOAuthAccessToken(
                details.getClientId(),
                "secret",
                testUser.getUserName(),
                TEST_PASSWORD,
                "oauth.approvals");
        Approval[] approvals = getApprovals(details.getClientId());
        assertThat(approvals).isEmpty();
        addApprovals(userToken, details.getClientId());
        approvals = getApprovals(details.getClientId());
        assertThat(approvals).hasSize(3);

        MockHttpServletRequestBuilder deleteClientsPost = post("/oauth/clients/tx/delete")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(new ClientDetails[]{details}));
        ResultActions result = mockMvc.perform(deleteClientsPost);
        result.andExpect(status().isOk());

        ClientDetailsModification[] deleted = (ClientDetailsModification[]) arrayFromString(result.andReturn().getResponse().getContentAsString(), ClientDetailsModification[].class);
        assertThat(deleted[0].isApprovalsDeleted()).isTrue();
        verify(mockApplicationEventPublisher, times(2)).publishEvent(abstractUaaEventCaptor.capture());

        approvals = getApprovals(details.getClientId());
        assertThat(approvals).isEmpty();
    }

    @Test
    void approvalsAreDeleted2() throws Exception {
        ClientDetails details = createClient(adminToken, new RandomValueStringGenerator().generate(),
                SECRET, Collections.singleton("password"));
        String userToken = testClient.getUserOAuthAccessToken(
                details.getClientId(),
                "secret",
                testUser.getUserName(),
                TEST_PASSWORD,
                "oauth.approvals");
        Approval[] approvals = getApprovals(details.getClientId());
        assertThat(approvals).isEmpty();
        addApprovals(userToken, details.getClientId());
        approvals = getApprovals(details.getClientId());
        assertThat(approvals).hasSize(3);

        MockHttpServletRequestBuilder deleteClientsPost = delete("/oauth/clients/" + details.getClientId())
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON);
        ResultActions result = mockMvc.perform(deleteClientsPost);
        result.andExpect(status().isOk());

        ClientDetails approvalsClient = createApprovalsLoginClient(adminToken);
        String loginToken = testClient.getUserOAuthAccessToken(
                approvalsClient.getClientId(),
                "secret",
                testUser.getUserName(),
                TEST_PASSWORD,
                "oauth.approvals");

        approvals = getApprovals(details.getClientId());
        assertThat(approvals).isEmpty();
    }

    @Test
    void modifyApprovalsAreDeleted() throws Exception {
        ClientDetails details = createClient(adminToken, new RandomValueStringGenerator().generate(),
                SECRET, Collections.singleton("password"));
        ((ClientDetailsModification) details).setAction(ClientDetailsModification.DELETE);
        String userToken = testClient.getUserOAuthAccessToken(
                details.getClientId(),
                "secret",
                testUser.getUserName(),
                TEST_PASSWORD,
                "oauth.approvals");
        Approval[] approvals = getApprovals(details.getClientId());
        assertThat(approvals).isEmpty();
        addApprovals(userToken, details.getClientId());
        approvals = getApprovals(details.getClientId());
        assertThat(approvals).hasSize(3);

        MockHttpServletRequestBuilder deleteClientsPost = post("/oauth/clients/tx/modify")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(new ClientDetails[]{details}));
        ResultActions result = mockMvc.perform(deleteClientsPost);
        result.andExpect(status().isOk());
        ClientDetailsModification[] deleted = (ClientDetailsModification[]) arrayFromString(result.andReturn().getResponse().getContentAsString(), ClientDetailsModification[].class);
        assertThat(deleted[0].isApprovalsDeleted()).isTrue();
        verify(mockApplicationEventPublisher, times(2)).publishEvent(abstractUaaEventCaptor.capture());

        ClientDetails approvalsClient = createApprovalsLoginClient(adminToken);
        String loginToken = testClient.getUserOAuthAccessToken(
                approvalsClient.getClientId(),
                "secret",
                testUser.getUserName(),
                TEST_PASSWORD,
                "oauth.approvals");
        approvals = getApprovals(details.getClientId());
        assertThat(approvals).isEmpty();
    }

    @Test
    void secretChangeTxApprovalsNotDeleted() throws Exception {
        int count = 3;
        //create clients
        ClientDetailsModification[] clients = createBaseClients(count, SECRET, Arrays.asList("client_credentials", "password"));
        for (ClientDetailsModification c : clients) {
            c.setAction(ClientDetailsModification.ADD);
        }
        MockHttpServletRequestBuilder modifyClientsPost = post("/oauth/clients/tx/modify")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(clients));
        ResultActions result = mockMvc.perform(modifyClientsPost);
        result.andExpect(status().isOk());

        //add approvals to the client
        for (ClientDetailsModification c : clients) {
            String userToken = testClient.getUserOAuthAccessToken(
                    c.getClientId(),
                    "secret",
                    testUser.getUserName(),
                    TEST_PASSWORD,
                    "oauth.approvals");
            addApprovals(userToken, c.getClientId());
        }

        //verify approvals to the client
        for (ClientDetailsModification c : clients) {
            String userToken = testClient.getUserOAuthAccessToken(
                    c.getClientId(),
                    "secret",
                    testUser.getUserName(),
                    TEST_PASSWORD,
                    "oauth.approvals");
            assertThat(getApprovals(c.getClientId())).hasSize(3);
        }

        //change the secret, and we know the old secret
        SecretChangeRequest[] srs = new SecretChangeRequest[clients.length];
        for (int i = 0; i < srs.length; i++) {
            srs[i] = new SecretChangeRequest();
            srs[i].setClientId(clients[i].getClientId());
            srs[i].setOldSecret(clients[i].getClientSecret());
            srs[i].setSecret("secret2");
        }
        modifyClientsPost = post("/oauth/clients/tx/secret")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(srs));
        result = mockMvc.perform(modifyClientsPost);
        result.andExpect(status().isOk());

        clients = (ClientDetailsModification[]) arrayFromString(result.andReturn().getResponse().getContentAsString(), ClientDetailsModification[].class);

        //check that we still have approvals for each client
        ClientDetails approvalsClient = createApprovalsLoginClient(adminToken);

        for (ClientDetailsModification c : clients) {
            String loginToken = testClient.getUserOAuthAccessToken(
                    approvalsClient.getClientId(),
                    "secret",
                    testUser.getUserName(),
                    TEST_PASSWORD,
                    "oauth.approvals");
            assertThat(getApprovals(c.getClientId())).hasSize(3);
            assertThat(c.isApprovalsDeleted()).isFalse();
        }

    }

    @Nested
    @DefaultTestContext
    @ExtendWith(ZoneSeederExtension.class)
    class WithUserWithClientsSecret {
        private ZoneSeeder zoneSeeder;
        private String userAccessToken;
        private String oldPassword;
        private TestClient testClient;

        @BeforeEach
        void setup(ZoneSeeder zoneSeeder, @Autowired TestClient testClient) {
            this.testClient = testClient;
            this.zoneSeeder = zoneSeeder
                    .withDefaults()
                    .withClientWithImplicitPasswordRefreshTokenGrants("clientId", "clients.secret")
                    .withClientWithImplicitPasswordRefreshTokenGrants("foobar", "clients.secret")
                    .withUserWhoBelongsToGroups("ihaveclientssecret@example.invalid", Collections.singletonList("clients.secret"))
                    .afterSeeding(zs -> {
                        ScimUser userByEmail = zs.getUserByEmail("ihaveclientssecret@example.invalid");

                        ClientDetails client = zoneSeeder.getClientById("clientId");
                        oldPassword = zs.getPlainTextClientSecret(client);
                        userAccessToken = getAccessTokenForUser(
                                testClient,
                                userByEmail,
                                client,
                                oldPassword,
                                zs);
                    });
        }

        private String getAccessTokenForUser(
                final TestClient testClient,
                final ScimUser scimUser,
                final ClientDetails client,
                final String oldPassword,
                final ZoneSeeder zoneSeeder) throws Exception {

            return testClient.getUserOAuthAccessTokenForZone(
                    client.getClientId(),
                    oldPassword,
                    scimUser.getUserName(),
                    zoneSeeder.getPlainTextPassword(scimUser),
                    "clients.secret",
                    zoneSeeder.getIdentityZoneSubdomain());
        }

        @Test
        void changeClientIdSecret() throws Exception {
            SecretChangeRequest request = new SecretChangeRequest("clientId", oldPassword, "someothervalue");
            MockHttpServletRequestBuilder modifyClientsPost = put("/oauth/clients/clientId/secret")
                    .headers(zoneSeeder.getZoneSubdomainRequestHeader())
                    .with(httpBearer(userAccessToken))
                    .accept(APPLICATION_JSON)
                    .contentType(APPLICATION_JSON)
                    .content(JsonUtils.writeValueAsString(request));
            mockMvc.perform(modifyClientsPost)
                    .andExpect(status().isOk());
        }

        @Test
        void changeFoobarSecret() throws Exception {
            SecretChangeRequest request = new SecretChangeRequest("foobar", oldPassword, "someothervalue");
            MockHttpServletRequestBuilder modifyClientsPost = put("/oauth/clients/foobar/secret")
                    .headers(zoneSeeder.getZoneSubdomainRequestHeader())
                    .with(httpBearer(userAccessToken))
                    .accept(APPLICATION_JSON)
                    .contentType(APPLICATION_JSON)
                    .content(JsonUtils.writeValueAsString(request));
            mockMvc.perform(modifyClientsPost)
                    .andExpect(status().isBadRequest())
                    .andExpect(content().contentType(APPLICATION_JSON))
                    .andExpect(content().string("{\"error\":\"invalid_client\",\"error_description\":\"Bad request. Not permitted to change another client's secret\"}"));
        }
    }

    @Test
    void secretChangeEvent() throws Exception {
        String token = testClient.getClientCredentialsOAuthAccessToken(
                testAccounts.getAdminClientId(),
                testAccounts.getAdminClientSecret(),
                "uaa.admin,clients.secret");
        String id = "secretchangeevent";
        createClient(token, id, SECRET, Collections.singleton("client_credentials"));
        SecretChangeRequest request = new SecretChangeRequest(id, "secret", "newsecret");
        MockHttpServletRequestBuilder modifyClientsPost = put("/oauth/clients/" + id + "/secret")
                .header("Authorization", "Bearer " + token)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(request));
        mockMvc.perform(modifyClientsPost)
                .andExpect(status().isOk());
        verify(mockApplicationEventPublisher, times(2)).publishEvent(abstractUaaEventCaptor.capture());
        assertThat(abstractUaaEventCaptor.getValue().getClass()).isEqualTo(SecretChangeEvent.class);
        SecretChangeEvent event = (SecretChangeEvent) abstractUaaEventCaptor.getValue();
        assertThat(event.getAuditEvent().getPrincipalId()).isEqualTo(id);
    }

    @Test
    void addNewClientSecret() throws Exception {
        String token = testClient.getClientCredentialsOAuthAccessToken(
                testAccounts.getAdminClientId(),
                testAccounts.getAdminClientSecret(),
                "uaa.admin,clients.secret");
        String id = generator.generate();
        ClientDetails client = createClient(token, id, SECRET, Collections.singleton("client_credentials"));
        SecretChangeRequest request = new SecretChangeRequest();
        request.setSecret("password2");
        request.setChangeMode(ADD);
        MockHttpServletResponse response = mockMvc.perform(put("/oauth/clients/{client_id}/secret", client.getClientId())
                        .header("Authorization", "Bearer " + token)
                        .accept(APPLICATION_JSON)
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andReturn().getResponse();

        ActionResult actionResult = JsonUtils.readValue(response.getContentAsString(), ActionResult.class);
        assertThat(actionResult.getStatus()).isEqualTo("ok");
        assertThat(actionResult.getMessage()).isEqualTo("Secret is added");

        verify(mockApplicationEventPublisher, times(2)).publishEvent(abstractUaaEventCaptor.capture());
        assertThat(abstractUaaEventCaptor.getValue().getClass()).isEqualTo(SecretChangeEvent.class);
        SecretChangeEvent event = (SecretChangeEvent) abstractUaaEventCaptor.getValue();
        assertThat(event.getAuditEvent().getPrincipalId()).isEqualTo(id);
    }

    @Test
    void addMoreThanTwoClientSecret() throws Exception {
        String token = testClient.getClientCredentialsOAuthAccessToken(
                testAccounts.getAdminClientId(),
                testAccounts.getAdminClientSecret(),
                "uaa.admin,clients.secret");
        String id = generator.generate();
        ClientDetails client = createClient(token, id, SECRET, Collections.singleton("client_credentials"));
        SecretChangeRequest request = new SecretChangeRequest();
        request.setSecret("password2");
        request.setChangeMode(ADD);
        mockMvc.perform(put("/oauth/clients/{client_id}/secret", client.getClientId())
                        .header("Authorization", "Bearer " + token)
                        .accept(APPLICATION_JSON)
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(request)))
                .andExpect(status().isOk());

        request.setSecret("password3");
        MockHttpServletResponse response = mockMvc.perform(put("/oauth/clients/{client_id}/secret", client.getClientId())
                        .header("Authorization", "Bearer " + token)
                        .accept(APPLICATION_JSON)
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andReturn().getResponse();

        InvalidClientException invalidClientDetailsException = JsonUtils.readValue(response.getContentAsString(), InvalidClientException.class);
        assertThat(invalidClientDetailsException.getOAuth2ErrorCode()).isEqualTo("invalid_client");
        assertThat(invalidClientDetailsException.getMessage()).isEqualTo("client secret is either empty or client already has two secrets.");
        verify(mockApplicationEventPublisher, times(3)).publishEvent(abstractUaaEventCaptor.capture());
        assertThat(abstractUaaEventCaptor.getValue().getClass()).isEqualTo(SecretFailureEvent.class);
        SecretFailureEvent event = (SecretFailureEvent) abstractUaaEventCaptor.getValue();
        assertThat(event.getAuditEvent().getPrincipalId()).isEqualTo(id);
    }

    @Test
    void deleteClientSecret() throws Exception {
        String token = testClient.getClientCredentialsOAuthAccessToken(
                testAccounts.getAdminClientId(),
                testAccounts.getAdminClientSecret(),
                "uaa.admin,clients.secret");
        String id = generator.generate();
        ClientDetails client = createClient(token, id, SECRET, Collections.singleton("client_credentials"));
        SecretChangeRequest request = new SecretChangeRequest();
        request.setSecret("password2");
        request.setChangeMode(ADD);
        mockMvc.perform(put("/oauth/clients/{client_id}/secret", client.getClientId())
                        .header("Authorization", "Bearer " + token)
                        .accept(APPLICATION_JSON)
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(request)))
                .andExpect(status().isOk());

        request = new SecretChangeRequest();
        request.setChangeMode(DELETE);
        MockHttpServletResponse response = mockMvc.perform(put("/oauth/clients/{client_id}/secret", client.getClientId())
                        .header("Authorization", "Bearer " + token)
                        .accept(APPLICATION_JSON)
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andReturn().getResponse();

        ActionResult actionResult = JsonUtils.readValue(response.getContentAsString(), ActionResult.class);
        assertThat(actionResult).isNotNull();
        assertThat(actionResult.getStatus()).isEqualTo("ok");
        assertThat(actionResult.getMessage()).isEqualTo("Secret is deleted");

        verify(mockApplicationEventPublisher, times(3)).publishEvent(abstractUaaEventCaptor.capture());
        assertThat(abstractUaaEventCaptor.getValue().getClass()).isEqualTo(SecretChangeEvent.class);
        SecretChangeEvent event = (SecretChangeEvent) abstractUaaEventCaptor.getValue();
        assertThat(event.getAuditEvent().getPrincipalId()).isEqualTo(id);
    }

    @Test
    void deleteClientSecretForClientWithOneSecret() throws Exception {
        String token = testClient.getClientCredentialsOAuthAccessToken(
                testAccounts.getAdminClientId(),
                testAccounts.getAdminClientSecret(),
                "uaa.admin,clients.secret");
        String id = generator.generate();
        ClientDetails client = createClient(token, id, SECRET, Collections.singleton("client_credentials"));

        SecretChangeRequest request = new SecretChangeRequest();
        request.setChangeMode(DELETE);
        MockHttpServletResponse response = mockMvc.perform(put("/oauth/clients/{client_id}/secret", client.getClientId())
                        .header("Authorization", "Bearer " + token)
                        .accept(APPLICATION_JSON)
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andReturn().getResponse();

        InvalidClientException invalidClientDetailsException = JsonUtils.readValue(response.getContentAsString(), InvalidClientException.class);
        assertThat(invalidClientDetailsException.getOAuth2ErrorCode()).isEqualTo("invalid_client");
        assertThat(invalidClientDetailsException.getMessage()).isEqualTo("client secret is either empty or client has only one secret.");

        verify(mockApplicationEventPublisher, times(2)).publishEvent(abstractUaaEventCaptor.capture());
        assertThat(abstractUaaEventCaptor.getValue().getClass()).isEqualTo(SecretFailureEvent.class);
        SecretFailureEvent event = (SecretFailureEvent) abstractUaaEventCaptor.getValue();
        assertThat(event.getAuditEvent().getPrincipalId()).isEqualTo(id);
    }

    @Test
    void secretChangeUsingAdminClientToken() throws Exception {
        String adminToken = testClient.getClientCredentialsOAuthAccessToken(
                testAccounts.getAdminClientId(),
                testAccounts.getAdminClientSecret(),
                "uaa.admin");
        String id = generator.generate();
        createClient(adminToken, id, SECRET, Collections.singleton("client_credentials"));
        SecretChangeRequest request = new SecretChangeRequest(id, null, "newsecret");

        MockHttpServletRequestBuilder modifySecret = put("/oauth/clients/" + id + "/secret")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(request));

        mockMvc.perform(modifySecret).andExpect(status().isOk());
    }

    @Test
    void secretChangeUsingClientAdminToken() throws Exception {
        String adminToken = testClient.getClientCredentialsOAuthAccessToken(
                testAccounts.getAdminClientId(),
                testAccounts.getAdminClientSecret(),
                "clients.admin");
        String id = generator.generate();
        createClient(adminToken, id, SECRET, Collections.singleton("client_credentials"));
        SecretChangeRequest request = new SecretChangeRequest(id, null, "newersecret");

        MockHttpServletRequestBuilder modifySecret = put("/oauth/clients/" + id + "/secret")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(request));

        mockMvc.perform(modifySecret).andExpect(status().isOk());
    }

    @Test
    void unsuccessfulSecretChangeEvent() throws Exception {

        List<String> scopes = Arrays.asList("oauth.approvals", "clients.secret");
        UaaClientDetails client = createBaseClient(null, SECRET, Arrays.asList("password", "client_credentials"), scopes, scopes);
        MockHttpServletRequestBuilder createClientPost = post("/oauth/clients")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(client));
        mockMvc.perform(createClientPost).andExpect(status().isCreated());

        String clientSecretToken = testClient.getClientCredentialsOAuthAccessToken(client.getClientId(), client.getClientSecret(), "clients.secret");

        SecretChangeRequest request = new SecretChangeRequest(client.getClientId(), "invalidsecret", "newsecret");
        MockHttpServletRequestBuilder modifyClientsPost = put("/oauth/clients/" + client.getClientId() + "/secret")
                .header("Authorization", "Bearer " + clientSecretToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(request));
        mockMvc.perform(modifyClientsPost)
                .andExpect(status().isBadRequest());
        verify(mockApplicationEventPublisher, times(2)).publishEvent(abstractUaaEventCaptor.capture());
        assertThat(abstractUaaEventCaptor.getValue().getClass()).isEqualTo(SecretFailureEvent.class);
        SecretFailureEvent event = (SecretFailureEvent) abstractUaaEventCaptor.getValue();
        assertThat(event.getAuditEvent().getPrincipalId()).isEqualTo(client.getClientId());
    }

    @Test
    void secretChangeModifyTxApprovalsDeleted() throws Exception {
        int count = 3;
        //create clients
        ClientDetailsModification[] clients = createBaseClients(count, SECRET, Arrays.asList("client_credentials", "password"));
        for (ClientDetailsModification c : clients) {
            c.setAction(ClientDetailsModification.ADD);
        }
        MockHttpServletRequestBuilder modifyClientsPost = post("/oauth/clients/tx/modify")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(clients));
        ResultActions result = mockMvc.perform(modifyClientsPost);
        result.andExpect(status().isOk());

        clients = (ClientDetailsModification[]) arrayFromString(result.andReturn().getResponse().getContentAsString(), ClientDetailsModification[].class);

        //add approvals to the client
        for (ClientDetailsModification c : clients) {
            String userToken = testClient.getUserOAuthAccessToken(
                    c.getClientId(),
                    "secret",
                    testUser.getUserName(),
                    TEST_PASSWORD,
                    "oauth.approvals");
            addApprovals(userToken, c.getClientId());
        }

        //verify approvals to the client
        for (ClientDetailsModification c : clients) {
            String userToken = testClient.getUserOAuthAccessToken(
                    c.getClientId(),
                    "secret",
                    testUser.getUserName(),
                    TEST_PASSWORD,
                    "oauth.approvals");
            assertThat(getApprovals(c.getClientId())).hasSize(3);
        }

        //change the secret, and we know don't the old secret
        for (ClientDetailsModification c : clients) {
            c.setClientSecret("secret2");
            c.setAction(ClientDetailsModification.UPDATE_SECRET);
        }
        modifyClientsPost = post("/oauth/clients/tx/modify")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(clients));
        result = mockMvc.perform(modifyClientsPost);
        result.andExpect(status().isOk());
        clients = (ClientDetailsModification[]) arrayFromString(result.andReturn().getResponse().getContentAsString(), ClientDetailsModification[].class);

        //check that we deleted approvals for each client
        for (ClientDetailsModification c : clients) {
            String userToken = testClient.getUserOAuthAccessToken(
                    c.getClientId(),
                    "secret2",
                    testUser.getUserName(),
                    TEST_PASSWORD,
                    "oauth.approvals");
            assertThat(getApprovals(c.getClientId())).isEmpty();
            assertThat(c.isApprovalsDeleted()).isTrue();
        }

        //verify(mockApplicationEventPublisher, times(count*3)).publishEvent(abstractUaaEventCaptor.capture());
        verify(mockApplicationEventPublisher, times(12)).publishEvent(abstractUaaEventCaptor.capture());
        int index = 0;
        for (AbstractUaaEvent event : abstractUaaEventCaptor.getAllValues()) {
            if (index < count) {
                assertThat(event.getAuditEvent().getType()).isEqualTo(AuditEventType.ClientCreateSuccess);
            } else {
                int swit = index % 3;
                if (swit == 0) {
                    assertThat(event.getAuditEvent().getType()).isEqualTo(AuditEventType.ClientUpdateSuccess);
                } else if (swit == 1) {
                    assertThat(event.getAuditEvent().getType()).isEqualTo(AuditEventType.SecretChangeSuccess);
                } else {
                    assertThat(event.getAuditEvent().getType()).isEqualTo(AuditEventType.ClientApprovalsDeleted);
                    assertThat(event.getClass()).isEqualTo(ClientApprovalsDeletedEvent.class);
                }
            }

            index++;
        }
    }

    @Test
    void secretChangeModifyTxApprovalsNotDeleted() throws Exception {
        //create clients
        ClientDetailsModification[] clients = createBaseClients(3, SECRET, Arrays.asList("client_credentials", "password"));
        for (ClientDetailsModification c : clients) {
            c.setAction(ClientDetailsModification.ADD);
        }
        MockHttpServletRequestBuilder modifyClientsPost = post("/oauth/clients/tx/modify")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(clients));
        ResultActions result = mockMvc.perform(modifyClientsPost);
        result.andExpect(status().isOk());

        clients = (ClientDetailsModification[]) arrayFromString(result.andReturn().getResponse().getContentAsString(), ClientDetailsModification[].class);

        //add approvals to the client
        for (ClientDetailsModification c : clients) {
            String userToken = testClient.getUserOAuthAccessToken(
                    c.getClientId(),
                    "secret",
                    testUser.getUserName(),
                    TEST_PASSWORD,
                    "oauth.approvals");
            addApprovals(userToken, c.getClientId());
        }

        //verify approvals to the client
        for (ClientDetailsModification c : clients) {
            String userToken = testClient.getUserOAuthAccessToken(
                    c.getClientId(),
                    "secret",
                    testUser.getUserName(),
                    TEST_PASSWORD,
                    "oauth.approvals");
            assertThat(getApprovals(c.getClientId())).hasSize(3);
        }

        //change the secret, and we know don't the old secret
        for (ClientDetailsModification c : clients) {
            c.setClientSecret("secret");
            c.setAction(ClientDetailsModification.UPDATE_SECRET);
        }
        modifyClientsPost = post("/oauth/clients/tx/modify")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(clients));
        result = mockMvc.perform(modifyClientsPost);
        result.andExpect(status().isOk());

        clients = (ClientDetailsModification[]) arrayFromString(result.andReturn().getResponse().getContentAsString(), ClientDetailsModification[].class);

        //check that we still have approvals for each client
        for (ClientDetailsModification c : clients) {
            assertThat(c.isApprovalsDeleted()).isFalse();
            String userToken = testClient.getUserOAuthAccessToken(
                    c.getClientId(),
                    "secret",
                    testUser.getUserName(),
                    TEST_PASSWORD,
                    "oauth.approvals");
            assertThat(getApprovals(c.getClientId())).hasSize(3);
        }
    }

    @Test
    void clientsAdminPermissions() throws Exception {
        ClientDetails adminsClient = createClientAdminsClient(adminToken);

        //create clients
        ClientDetailsModification[] clients = createBaseClients(3, SECRET, Arrays.asList("client_credentials", "refresh_token"));
        for (ClientDetailsModification c : clients) {
            c.setScope(Collections.singletonList("oauth.approvals"));
            c.setAction(ClientDetailsModification.ADD);
        }

        String token = testClient.getClientCredentialsOAuthAccessToken(
                adminsClient.getClientId(),
                "secret",
                "clients.admin");

        MockHttpServletRequestBuilder modifyClientsPost = post("/oauth/clients/tx/modify")
                .header("Authorization", "Bearer " + token)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(clients));
        ResultActions result = mockMvc.perform(modifyClientsPost);
        result.andExpect(status().isOk());
    }

    @Test
    void nonClientsAdminPermissions() throws Exception {
        ClientDetails adminsClient = createReadWriteClient(adminToken);

        //create clients
        ClientDetailsModification[] clients = createBaseClients(3, SECRET, Arrays.asList("client_credentials", "refresh_token"));
        for (ClientDetailsModification c : clients) {
            c.setScope(Collections.singletonList("oauth.approvals"));
            c.setAction(ClientDetailsModification.ADD);
        }

        String token = testClient.getClientCredentialsOAuthAccessToken(
                adminsClient.getClientId(),
                "secret",
                "clients.write");

        MockHttpServletRequestBuilder modifyClientsPost = post("/oauth/clients/tx/modify")
                .header("Authorization", "Bearer " + token)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(clients));
        ResultActions result = mockMvc.perform(modifyClientsPost);
        result.andExpect(status().isForbidden());
    }

    @Test
    void createAsAdminPermissions() throws Exception {
        ClientDetails adminsClient = createClientAdminsClient(adminToken);

        //create clients
        ClientDetailsModification[] clients = createBaseClients(1, SECRET, Arrays.asList("client_credentials", "refresh_token"));
        for (ClientDetailsModification c : clients) {
            c.setScope(Collections.singletonList("oauth.approvals"));
            c.setAction(ClientDetailsModification.ADD);
        }

        String token = testClient.getClientCredentialsOAuthAccessToken(
                adminsClient.getClientId(),
                "secret",
                "clients.admin");

        MockHttpServletRequestBuilder modifyClientsPost = post("/oauth/clients")
                .header("Authorization", "Bearer " + token)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(clients[0]));
        ResultActions result = mockMvc.perform(modifyClientsPost);
        result.andExpect(status().isCreated());
    }

    @Test
    void createAsReadPermissions() throws Exception {
        ClientDetails adminsClient = createReadWriteClient(adminToken);

        //create clients
        ClientDetailsModification[] clients = createBaseClients(1, SECRET, Arrays.asList("client_credentials", "refresh_token"));
        for (ClientDetailsModification c : clients) {
            c.setScope(Collections.singletonList("oauth.approvals"));
            c.setAction(ClientDetailsModification.ADD);
        }

        String token = testClient.getClientCredentialsOAuthAccessToken(
                adminsClient.getClientId(),
                "secret",
                "clients.read");

        MockHttpServletRequestBuilder modifyClientsPost = post("/oauth/clients")
                .header("Authorization", "Bearer " + token)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(clients[0]));
        ResultActions result = mockMvc.perform(modifyClientsPost);
        result.andExpect(status().isForbidden());
    }

    @Test
    void createAsWritePermissions() throws Exception {
        ClientDetails adminsClient = createReadWriteClient(adminToken);

        //create clients
        ClientDetailsModification[] clients = createBaseClients(1, SECRET, Arrays.asList("client_credentials", "refresh_token"));
        for (ClientDetailsModification c : clients) {
            c.setScope(Collections.singletonList("oauth.approvals"));
            c.setAction(ClientDetailsModification.ADD);
        }

        String token = testClient.getClientCredentialsOAuthAccessToken(
                adminsClient.getClientId(),
                "secret",
                "clients.write");

        MockHttpServletRequestBuilder modifyClientsPost = post("/oauth/clients")
                .header("Authorization", "Bearer " + token)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(clients[0]));
        ResultActions result = mockMvc.perform(modifyClientsPost);
        result.andExpect(status().isCreated());
    }

    @Test
    void getClientDetailsSortedByLastModified() throws Exception {

        ClientDetails adminsClient = createReadWriteClient(adminToken);

        String token = testClient.getClientCredentialsOAuthAccessToken(

                adminsClient.getClientId(),
                "secret",
                "clients.read");

        MockHttpServletRequestBuilder get = get("/oauth/clients")
                .header("Authorization", "Bearer " + token)
                .param("sortBy", "lastmodified")
                .param("sortOrder", "descending")
                .accept(APPLICATION_JSON);

        MvcResult result = mockMvc.perform(get).andExpect(status().isOk()).andReturn();
        String body = result.getResponse().getContentAsString();

        Collection<UaaClientDetails> clientDetails = JsonUtils.readValue(body, new TypeReference<SearchResults<UaaClientDetails>>() {
        }).getResources();

        assertThat(clientDetails).isNotNull();

        Date lastDate = null;

        for (ClientDetails clientDetail : clientDetails) {
            assertThat(clientDetail.getAdditionalInformation()).containsKey("lastModified");

            Date currentDate = JsonUtils.convertValue(clientDetail.getAdditionalInformation().get("lastModified"), Date.class);

            if (lastDate != null) {
                assertThat(currentDate).isBeforeOrEqualTo(lastDate);
            }

            lastDate = currentDate;
        }
    }

    @Test
    void getClientsLargerThanMaxWhenCountParamIsProvided() throws Exception {
        for (int i = 0; i < 7; i++) {
            clientDetails.add(
                    createClient(
                            adminToken,
                            "testclient" + new RandomValueStringGenerator().generate(),
                            SECRET,
                            Collections.singleton("client_credentials")
                    )
            );
        }

        ClientDetails adminsClient = createReadWriteClient(adminToken);

        String token = testClient.getClientCredentialsOAuthAccessToken(
                adminsClient.getClientId(),
                "secret",
                "clients.read");

        MockHttpServletRequestBuilder get = get("/oauth/clients")
                .header("Authorization", "Bearer " + token)
                .param("count", "7")
                .accept(APPLICATION_JSON);

        MvcResult result = mockMvc.perform(get).andExpect(status().isOk()).andReturn();
        String body = result.getResponse().getContentAsString();

        SearchResults<UaaClientDetails> clientDetailsSearchResults = JsonUtils.readValue(body, new TypeReference<SearchResults<UaaClientDetails>>() {
        });

        assertThat(clientDetailsSearchResults.getItemsPerPage()).isEqualTo(clientMaxCount);
        assertThat(clientDetailsSearchResults.getTotalResults()).isGreaterThan(6);
        assertThat(clientDetailsSearchResults.getStartIndex()).isOne();
        assertThat(clientDetailsSearchResults.getResources()).hasSize(clientMaxCount);
    }

    @Test
    void getClientsLargerThanMaxWhenNoCountParamIsProvided() throws Exception {
        int numOfClientsCreated = 7;
        for (int i = 0; i < numOfClientsCreated; i++) {
            clientDetails.add(
                    createClient(
                            adminToken,
                            "testclient" + new RandomValueStringGenerator().generate(),
                            SECRET,
                            Collections.singleton("client_credentials")
                    )
            );
        }

        ClientDetails adminsClient = createReadWriteClient(adminToken);

        String token = testClient.getClientCredentialsOAuthAccessToken(
                adminsClient.getClientId(),
                "secret",
                "clients.read");

        MockHttpServletRequestBuilder get = get("/oauth/clients")
                .header("Authorization", "Bearer " + token)
                .accept(APPLICATION_JSON);

        MvcResult result = mockMvc.perform(get).andExpect(status().isOk()).andReturn();
        String body = result.getResponse().getContentAsString();

        SearchResults<UaaClientDetails> clientDetailsSearchResults = JsonUtils.readValue(body, new TypeReference<SearchResults<UaaClientDetails>>() {
        });

        assertThat(clientDetailsSearchResults.getItemsPerPage()).isEqualTo(clientMaxCount);
        assertThat(clientDetailsSearchResults.getTotalResults()).isGreaterThan(numOfClientsCreated);
        assertThat(clientDetailsSearchResults.getStartIndex()).isOne();
        assertThat(clientDetailsSearchResults.getResources()).hasSize(clientMaxCount);
    }

    @Test
    void clientWithDotInID() throws Exception {
        createClient(adminToken, "testclient", SECRET, Collections.singleton("client_credentials"));
        ClientDetails detailsv2 = createClient(adminToken, "testclient.v2", SECRET,
                Collections.singleton("client_credentials"));
        assertThat(detailsv2.getClientId()).isEqualTo("testclient.v2");
    }

    @Test
    void putClientModifyAuthorities() throws Exception {
        ClientDetails client = createClient(adminToken, "testClientForModifyAuthorities",
                SECRET, Collections.singleton("client_credentials"));

        UaaClientDetails modified = new UaaClientDetails(client);
        modified.setAuthorities(Collections.singleton((GrantedAuthority) () -> "newAuthority"));

        MockHttpServletRequestBuilder put = put("/oauth/clients/" + client.getClientId())
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(modified));
        mockMvc.perform(put).andExpect(status().isOk()).andReturn();

        client = getClient(client.getClientId());
        assertThat(client.getAuthorities()).hasSize(1);
        GrantedAuthority authority = Iterables.get(client.getAuthorities(), 0);
        assertThat(authority.getAuthority()).isEqualTo("newAuthority");
    }

    @Test
    void putClientModifyAccessTokenValidity() throws Exception {
        ClientDetails client = createClient(adminToken, "testClientForModifyAccessTokenValidity",
                SECRET, Collections.singleton("client_credentials"));

        UaaClientDetails modified = new UaaClientDetails(client);
        modified.setAccessTokenValiditySeconds(73);

        MockHttpServletRequestBuilder put = put("/oauth/clients/" + client.getClientId())
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(modified));
        mockMvc.perform(put).andExpect(status().isOk()).andReturn();

        client = getClient(client.getClientId());
        assertThat(client.getAccessTokenValiditySeconds()).isEqualTo(73);
    }

    @Test
    void putClientModifyName() throws Exception {
        ClientDetails client = createClient(adminToken, "testClientForModifyName",
                SECRET, Collections.singleton("client_credentials"));

        Map<String, Object> requestBody = JsonUtils.readValue(JsonUtils.writeValueAsString(new UaaClientDetails(client)), new TypeReference<Map<String, Object>>() {
        });
        requestBody.put("name", "New Client Name");

        MockHttpServletRequestBuilder put = put("/oauth/clients/" + client.getClientId())
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(requestBody));
        mockMvc.perform(put).andExpect(status().isOk()).andReturn();

        MockHttpServletRequestBuilder getClient = get("/oauth/clients/" + client.getClientId())
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON);
        ResultActions result11 = mockMvc.perform(getClient);
        MockHttpServletResponse response = result11.andReturn().getResponse();
        Map<String, Object> map = JsonUtils.readValue(response.getContentAsString(), new TypeReference<Map<String, Object>>() {
        });
        assertThat(map).containsEntry("name", "New Client Name");

        ClientDetails result;
        int responseCode = response.getStatus();
        HttpStatus status = HttpStatus.valueOf(responseCode);
        String body = response.getContentAsString();
        if (status == HttpStatus.OK) {
            result = clientFromString(body);
        } else if (status == HttpStatus.NOT_FOUND) {
            result = null;
        } else {
            throw new InvalidClientDetailsException(status + " : " + body);
        }
        client = result;
        assertThat(client.getAdditionalInformation()).containsEntry("name", "New Client Name");
    }

    @Test
    void addNewClientJwtKeyUri() throws Exception {
        String token = testClient.getClientCredentialsOAuthAccessToken(
                testAccounts.getAdminClientId(),
                testAccounts.getAdminClientSecret(),
                "uaa.admin,clients.secret");
        String id = generator.generate();
        ClientDetails client = createClient(token, id, SECRET, Collections.singleton("client_credentials"));
        ClientJwtChangeRequest request = new ClientJwtChangeRequest(null, null, null);
        request.setJsonWebKeyUri("http://localhost:8080/uaa/token_key");
        request.setClientId("admin");
        request.setChangeMode(ClientJwtChangeRequest.ChangeMode.ADD);
        MockHttpServletResponse response = mockMvc.perform(put("/oauth/clients/{client_id}/clientjwt", client.getClientId())
                        .header("Authorization", "Bearer " + token)
                        .accept(APPLICATION_JSON)
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andReturn().getResponse();

        ActionResult actionResult = JsonUtils.readValue(response.getContentAsString(), ActionResult.class);
        assertThat(actionResult.getStatus()).isEqualTo("ok");
        assertThat(actionResult.getMessage()).isEqualTo("Client jwt configuration is added");

        verify(mockApplicationEventPublisher, times(2)).publishEvent(abstractUaaEventCaptor.capture());
        assertThat(abstractUaaEventCaptor.getValue().getClass()).isEqualTo(ClientJwtChangeEvent.class);
        ClientJwtChangeEvent event = (ClientJwtChangeEvent) abstractUaaEventCaptor.getValue();
        assertThat(event.getAuditEvent().getPrincipalId()).isEqualTo(id);
    }

    @Test
    void addNewClientJwtKeyUriButInvalidChange() throws Exception {
        String token = testClient.getClientCredentialsOAuthAccessToken(
                testAccounts.getAdminClientId(),
                testAccounts.getAdminClientSecret(),
                "uaa.admin,clients.secret");
        String id = generator.generate();
        ClientDetails client = createClient(token, id, SECRET, Collections.singleton("client_credentials"));
        ClientJwtChangeRequest request = new ClientJwtChangeRequest(null, null, null);
        request.setJsonWebKeyUri("http://localhost:8080/uaa/token_key");
        request.setClientId("admin");
        request.setChangeMode(ClientJwtChangeRequest.ChangeMode.ADD);
        MockHttpServletResponse response = mockMvc.perform(put("/oauth/clients/{client_id}/clientjwt", client.getClientId())
                        .header("Authorization", "Bearer " + token)
                        .accept(APPLICATION_JSON)
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andReturn().getResponse();

        ActionResult actionResult = JsonUtils.readValue(response.getContentAsString(), ActionResult.class);
        assertThat(actionResult.getStatus()).isEqualTo("ok");
        assertThat(actionResult.getMessage()).isEqualTo("Client jwt configuration is added");

        verify(mockApplicationEventPublisher, times(2)).publishEvent(abstractUaaEventCaptor.capture());
        assertThat(abstractUaaEventCaptor.getValue().getClass()).isEqualTo(ClientJwtChangeEvent.class);
        ClientJwtChangeEvent event = (ClientJwtChangeEvent) abstractUaaEventCaptor.getValue();
        assertThat(event.getAuditEvent().getPrincipalId()).isEqualTo(id);

        request = new ClientJwtChangeRequest("admin", null, "{\"keys\":[{\"kty\":\"RSA\",\"e\":\"AQAB\",\"use\":\"sig\",\"alg\":\"RS256\",\"n\":\"n\"}]}");
        request.setChangeMode(ClientJwtChangeRequest.ChangeMode.UPDATE);
        mockMvc.perform(put("/oauth/clients/{client_id}/clientjwt", client.getClientId())
                        .header("Authorization", "Bearer " + token)
                        .accept(APPLICATION_JSON)
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andReturn().getResponse();

        verify(mockApplicationEventPublisher, times(3)).publishEvent(abstractUaaEventCaptor.capture());
        assertThat(abstractUaaEventCaptor.getValue().getClass()).isEqualTo(ClientJwtFailureEvent.class);
        ClientJwtFailureEvent eventUpdate = (ClientJwtFailureEvent) abstractUaaEventCaptor.getValue();
        assertThat(eventUpdate.getAuditEvent().getPrincipalId()).isEqualTo(client.getClientId());
    }

    @Test
    void invalidClientJwtKeyUri() throws Exception {
        String token = testClient.getClientCredentialsOAuthAccessToken(
                testAccounts.getAdminClientId(),
                testAccounts.getAdminClientSecret(),
                "uaa.admin,clients.secret");
        String id = generator.generate();
        ClientDetails client = createClient(token, id, SECRET, Collections.singleton("client_credentials"));
        ClientJwtChangeRequest request = new ClientJwtChangeRequest(null, null, null);
        request.setJsonWebKeyUri("no uri");
        request.setClientId("admin");
        request.setChangeMode(ClientJwtChangeRequest.ChangeMode.ADD);
        mockMvc.perform(put("/oauth/clients/{client_id}/clientjwt", client.getClientId())
                        .header("Authorization", "Bearer " + token)
                        .accept(APPLICATION_JSON)
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andReturn().getResponse();

        verify(mockApplicationEventPublisher, times(2)).publishEvent(abstractUaaEventCaptor.capture());
        assertThat(abstractUaaEventCaptor.getValue().getClass()).isEqualTo(ClientJwtFailureEvent.class);
        ClientJwtFailureEvent event = (ClientJwtFailureEvent) abstractUaaEventCaptor.getValue();
        assertThat(event.getAuditEvent().getPrincipalId()).isEqualTo(client.getClientId());
    }

    private UaaClientDetails createClient(List<String> authorities) throws Exception {
        String clientId = generator.generate().toLowerCase();
        List<String> scopes = Arrays.asList("foo", "bar", "oauth.approvals");
        ClientDetailsModification client = createBaseClient(clientId, SECRET, Collections.singleton("client_credentials"), authorities, scopes);
        MockHttpServletRequestBuilder createClientPost = post("/oauth/clients")
                .header("Authorization", "Bearer " + adminUserToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(client));
        ResultActions createResult = mockMvc.perform(createClientPost).andExpect(status().isCreated());
        return JsonUtils.readValue(createResult.andReturn().getResponse().getContentAsString(), UaaClientDetails.class);
    }

    private ClientMetadata obtainClientMetadata(String clientId) throws Exception {
        MockHttpServletRequestBuilder getClientMetadata = get("/oauth/clients/" + clientId + "/meta")
                .header("Authorization", "Bearer " + adminUserToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON);
        ResultActions getResult = mockMvc.perform(getClientMetadata).andExpect(status().isOk());
        return JsonUtils.readValue(getResult.andReturn().getResponse().getContentAsString(), ClientMetadata.class);
    }

    private Approval[] getApprovals(String clientId) {
        return jdbcApprovalStore.getApprovalsForClient(clientId, IdentityZoneHolder.get().getId()).toArray(new Approval[0]);
    }

    private void setupAdminUserToken() throws Exception {
        HttpServletResponse mockResponse = mock(HttpServletResponse.class);

        SearchResults<Map<String, Object>> marissa = (SearchResults<Map<String, Object>>) scimUserEndpoints.findUsers("id,userName", "userName eq \"" + testUser.getUserName() + "\"", "userName", "asc", 0, 1);
        String marissaId = (String) marissa.getResources().getFirst().get("id");

        //add marissa to uaa.admin
        SearchResults<Map<String, Object>> uaaAdmin = (SearchResults<Map<String, Object>>) scimGroupEndpoints.listGroups("id,displayName", "displayName eq \"uaa.admin\"", "displayName", "asc", 1, 1);
        String groupId = (String) uaaAdmin.getResources().getFirst().get("id");
        ScimGroup group = scimGroupEndpoints.getGroup(groupId, mockResponse);
        ScimGroupMember gm = new ScimGroupMember(marissaId, ScimGroupMember.Type.USER);
        group.getMembers().add(gm);
        scimGroupEndpoints.updateGroup(group, groupId, String.valueOf(group.getVersion()), mockResponse);

        //add marissa to clients.write
        uaaAdmin = (SearchResults<Map<String, Object>>) scimGroupEndpoints.listGroups("id,displayName", "displayName eq \"clients.write\"", "displayName", "asc", 1, 1);
        groupId = (String) uaaAdmin.getResources().getFirst().get("id");
        group = scimGroupEndpoints.getGroup(groupId, mockResponse);
        gm = new ScimGroupMember(marissaId, ScimGroupMember.Type.USER);
        group.getMembers().add(gm);
        scimGroupEndpoints.updateGroup(group, groupId, String.valueOf(group.getVersion()), mockResponse);

        //add marissa to clients.read
        uaaAdmin = (SearchResults<Map<String, Object>>) scimGroupEndpoints.listGroups("id,displayName", "displayName eq \"clients.read\"", "displayName", "asc", 1, 1);
        groupId = (String) uaaAdmin.getResources().getFirst().get("id");
        group = scimGroupEndpoints.getGroup(groupId, mockResponse);
        gm = new ScimGroupMember(marissaId, ScimGroupMember.Type.USER);
        group.getMembers().add(gm);
        scimGroupEndpoints.updateGroup(group, groupId, String.valueOf(group.getVersion()), mockResponse);

        ClientDetails adminClient = createAdminClient(adminToken);

        adminUserToken = testClient.getUserOAuthAccessToken(adminClient.getClientId(),
                "secret",
                testUser.getUserName(),
                TEST_PASSWORD,
                "uaa.admin");
    }

    private void addApprovals(String token, String clientId) throws Exception {
        Date oneMinuteAgo = new Date(System.currentTimeMillis() - 60000);
        Date expiresAt = new Date(System.currentTimeMillis() + 60000);
        Approval[] approvals = new Approval[]{
                new Approval()
                        .setUserId(null)
                        .setClientId(clientId)
                        .setScope("cloud_controller.read")
                        .setExpiresAt(expiresAt)
                        .setStatus(ApprovalStatus.APPROVED)
                        .setLastUpdatedAt(oneMinuteAgo),
                new Approval()
                        .setUserId(null)
                        .setClientId(clientId)
                        .setScope("openid")
                        .setExpiresAt(expiresAt)
                        .setStatus(ApprovalStatus.APPROVED)
                        .setLastUpdatedAt(oneMinuteAgo),
                new Approval()
                        .setUserId(null)
                        .setClientId(clientId)
                        .setScope("password.write")
                        .setExpiresAt(expiresAt)
                        .setStatus(ApprovalStatus.APPROVED)
                        .setLastUpdatedAt(oneMinuteAgo)};

        MockHttpServletRequestBuilder put = put("/approvals/" + clientId)
                .header("Authorization", "Bearer " + token)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(approvals));
        mockMvc.perform(put).andExpect(status().isOk());
    }

    private ClientDetailsModification createBaseClient(String id, String clientSecret, Collection<String> grantTypes, List<String> authorities, List<String> scopes) {
        if (id == null) {
            id = new RandomValueStringGenerator().generate();
        }
        if (grantTypes == null) {
            grantTypes = Collections.singleton("client_credentials");
        }
        ClientDetailsModification client = new ClientDetailsModification();
        client.setClientId(id);
        client.setScope(scopes);
        client.setAuthorizedGrantTypes(grantTypes);
        if (authorities != null) {
            client.setAuthorities(AuthorityUtils.commaSeparatedStringToAuthorityList(String.join(",", authorities)));
        }
        client.setClientSecret(clientSecret);
        Map<String, Object> additionalInformation = new HashMap<>();
        additionalInformation.put("foo", "bar");
        additionalInformation.put("name", "Client " + id);
        client.setAdditionalInformation(additionalInformation);
        client.setRegisteredRedirectUri(Collections.singleton("http://some.redirect.url.com"));
        return client;
    }

    protected ClientDetails createClient(String token, String id, String clientSecret, Collection<String> grantTypes) throws Exception {
        UaaClientDetails client = createBaseClient(id, clientSecret, grantTypes);
        MockHttpServletRequestBuilder createClientPost = post("/oauth/clients")
                .header("Authorization", "Bearer " + token)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(client));
        mockMvc.perform(createClientPost).andExpect(status().isCreated());
        return getClient(client.getClientId());
    }

    private ClientDetails createClientAdminsClient(String token) throws Exception {
        List<String> scopes = Arrays.asList("oauth.approvals", "clients.admin");
        UaaClientDetails client = createBaseClient(null, SECRET, Arrays.asList("password", "client_credentials"), scopes, scopes);
        MockHttpServletRequestBuilder createClientPost = post("/oauth/clients")
                .header("Authorization", "Bearer " + token)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(client));
        mockMvc.perform(createClientPost).andExpect(status().isCreated());
        return getClient(client.getClientId());
    }

    private ClientDetails createReadWriteClient(String token) throws Exception {
        List<String> scopes = Arrays.asList("oauth.approvals", "clients.read", "clients.write");
        UaaClientDetails client = createBaseClient(null, SECRET, Arrays.asList("password", "client_credentials"), scopes, scopes);
        MockHttpServletRequestBuilder createClientPost = post("/oauth/clients")
                .header("Authorization", "Bearer " + token)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(client));
        mockMvc.perform(createClientPost).andExpect(status().isCreated());
        return getClient(client.getClientId());
    }

    private ClientDetails createAdminClient(String token) throws Exception {
        List<String> scopes = Arrays.asList("uaa.admin", "oauth.approvals", "clients.read", "clients.write");
        UaaClientDetails client = createBaseClient(null, SECRET, Arrays.asList("password", "client_credentials"), scopes, scopes);

        MockHttpServletRequestBuilder createClientPost = post("/oauth/clients")
                .header("Authorization", "Bearer " + token)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(client));
        mockMvc.perform(createClientPost).andExpect(status().isCreated());
        return getClient(client.getClientId());
    }

    private ClientDetailsModification createBaseClient(String id, String clientSecret, Collection<String> grantTypes) {
        return createBaseClient(id, clientSecret, grantTypes, Collections.singletonList("uaa.none"), Arrays.asList("foo", "bar", "oauth.approvals"));
    }

    private ClientDetailsModification[] createBaseClients(int length, String clientSecret, Collection<String> grantTypes) {
        ClientDetailsModification[] result = new ClientDetailsModification[length];
        for (int i = 0; i < result.length; i++) {
            result[i] = createBaseClient(null, clientSecret, grantTypes);
        }
        return result;
    }

    private ClientDetails getClient(String id) throws Exception {
        MockHttpServletRequestBuilder getClient = get("/oauth/clients/" + id)
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON);
        ResultActions result = mockMvc.perform(getClient);
        MockHttpServletResponse response = result.andReturn().getResponse();
        int responseCode = response.getStatus();
        HttpStatus status = HttpStatus.valueOf(responseCode);
        String body = response.getContentAsString();
        if (status == HttpStatus.OK) {
            return clientFromString(body);
        } else if (status == HttpStatus.NOT_FOUND) {
            return null;
        } else {
            throw new InvalidClientDetailsException(status + " : " + body);
        }
    }

    private ClientDetails createApprovalsLoginClient(String token) throws Exception {
        List<String> scopes = Arrays.asList("uaa.admin", "oauth.approvals", "oauth.login");
        UaaClientDetails client = createBaseClient(null, SECRET, Arrays.asList("password", "client_credentials"), scopes, scopes);

        MockHttpServletRequestBuilder createClientPost = post("/oauth/clients")
                .header("Authorization", "Bearer " + token)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(client));
        mockMvc.perform(createClientPost).andExpect(status().isCreated());
        return getClient(client.getClientId());
    }
}
