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
import org.cloudfoundry.identity.uaa.client.UaaScopes;
import org.cloudfoundry.identity.uaa.client.event.ClientAdminEventPublisher;
import org.cloudfoundry.identity.uaa.client.event.ClientApprovalsDeletedEvent;
import org.cloudfoundry.identity.uaa.client.event.ClientCreateEvent;
import org.cloudfoundry.identity.uaa.client.event.ClientDeleteEvent;
import org.cloudfoundry.identity.uaa.client.event.ClientUpdateEvent;
import org.cloudfoundry.identity.uaa.client.event.SecretChangeEvent;
import org.cloudfoundry.identity.uaa.client.event.SecretFailureEvent;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.oauth.client.ClientDetailsCreation;
import org.cloudfoundry.identity.uaa.oauth.client.ClientDetailsModification;
import org.cloudfoundry.identity.uaa.oauth.client.SecretChangeRequest;
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
import org.cloudfoundry.identity.uaa.util.PredicateMatcher;
import org.cloudfoundry.identity.uaa.zone.ClientSecretPolicy;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Disabled;
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
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.util.StringUtils;
import org.springframework.web.context.WebApplicationContext;

import javax.servlet.http.HttpServletResponse;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.mock.util.ClientDetailsHelper.arrayFromString;
import static org.cloudfoundry.identity.uaa.mock.util.ClientDetailsHelper.clientArrayFromString;
import static org.cloudfoundry.identity.uaa.mock.util.ClientDetailsHelper.clientFromString;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.httpBearer;
import static org.cloudfoundry.identity.uaa.oauth.client.SecretChangeRequest.ChangeMode.ADD;
import static org.cloudfoundry.identity.uaa.oauth.client.SecretChangeRequest.ChangeMode.DELETE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_JWT_BEARER;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.hasEntry;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.iterableWithSize;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
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
public class ClientAdminEndpointsMockMvcTests {

    private static final String SECRET = "secret";
    private static final String testPassword = "password";

    private String adminUserToken;
    private ScimUserEndpoints scimUserEndpoints;
    private ScimGroupEndpoints scimGroupEndpoints;
    private ApplicationEventPublisher mockApplicationEventPublisher;
    private ApplicationEventPublisher originalApplicationEventPublisher;
    private ArgumentCaptor<AbstractUaaEvent> abstractUaaEventCaptor;
    private ScimUser testUser;
    private RandomValueStringGenerator generator = new RandomValueStringGenerator(7);
    private static final String SECRET_TOO_LONG = Strings.repeat("a", 300);
    private List<ClientDetails> clientDetails;
    private int clientMaxCount;
    private String adminToken;
    private UaaTestAccounts testAccounts;

    private WebApplicationContext webApplicationContext;
    private MockMvc mockMvc;
    private TestClient testClient;
    private JdbcApprovalStore jdbcApprovalStore;

    @BeforeEach
    void setUp(
            @Autowired WebApplicationContext webApplicationContext,
            @Autowired MockMvc mockMvc,
            @Autowired TestClient testClient,
            @Autowired JdbcApprovalStore jdbcApprovalStore,
            @Autowired ScimUserEndpoints scimUserEndpoints,
            @Autowired ScimGroupEndpoints scimGroupEndpoints,
            @Autowired ClientAdminEventPublisher eventPublisher,
            @Value("${clientMaxCount}") int clientMaxCount
    ) throws Exception {
        this.webApplicationContext = webApplicationContext;
        this.mockMvc = mockMvc;
        this.testClient = testClient;
        this.jdbcApprovalStore = jdbcApprovalStore;
        this.scimUserEndpoints = scimUserEndpoints;
        this.scimGroupEndpoints = scimGroupEndpoints;
        this.clientMaxCount = clientMaxCount;

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
        testUser.setPassword(testPassword);
        testUser = MockMvcUtils.createUser(mockMvc, adminToken, testUser);
        testUser.setPassword(testPassword);
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
    void restorePublisher(
            @Autowired ClientAdminEventPublisher eventPublisher
    ) {
        eventPublisher.setApplicationEventPublisher(originalApplicationEventPublisher);
    }

    @Test
    void testCreateClient() throws Exception {
        ClientDetails client = createClient(adminToken, new RandomValueStringGenerator().generate(), SECRET,
                Collections.singleton("client_credentials"));
        verify(mockApplicationEventPublisher, times(1)).publishEvent(abstractUaaEventCaptor.capture());
        assertEquals(AuditEventType.ClientCreateSuccess, abstractUaaEventCaptor.getValue().getAuditEvent().getType());
        assertEquals("Client " + client.getClientId(), client.getAdditionalInformation().get("name"));
    }

    @Test
    void testCreateClientWithJwtBearerGrant() throws Exception {
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

    @Disabled("GE Fork has its own JWT-bearer implementation")
    @Test
    void testCreateClientWithJwtBearerGrantInvalid() throws Exception {
        String id = new RandomValueStringGenerator().generate();
        ClientDetails client = createBaseClient(id, SECRET, Collections.singletonList(GRANT_TYPE_JWT_BEARER), null, null);
        MockHttpServletRequestBuilder createClientPost = post("/oauth/clients")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(client));
        MvcResult mvcResult = mockMvc.perform(createClientPost).andExpect(status().isBadRequest()).andReturn();
        assertTrue(mvcResult.getResponse().getContentAsString().contains("Scope cannot be empty for grant_type " + GRANT_TYPE_JWT_BEARER));
        verify(mockApplicationEventPublisher, times(0)).publishEvent(abstractUaaEventCaptor.capture());
    }

    @Test
    void testCreateClientWithInvalidRedirectUrl() throws Exception {
        BaseClientDetails client = createBaseClient(new RandomValueStringGenerator().generate(), SECRET, Collections.singleton("implicit"));
        client.setRegisteredRedirectUri(Collections.singleton("*/**"));
        MockHttpServletRequestBuilder createClientPost = post("/oauth/clients")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(client));
        mockMvc.perform(createClientPost).andExpect(status().isBadRequest()).andReturn();
        verify(mockApplicationEventPublisher, times(0)).publishEvent(abstractUaaEventCaptor.capture());
    }

    // TODO: put in a nested context to clean up the excluded claims
    @Test
    void createClient_withClientAdminToken_withAuthoritiesExcluded(
            @Autowired @Qualifier("excludedClaims") LinkedHashSet excludedClaims
    ) throws Exception {
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
            BaseClientDetails clientDetails = JsonUtils.readValue(createResult.andReturn().getResponse().getContentAsString(), BaseClientDetails.class);
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
    void testCreateClient_With_Long_Secret() throws Exception {
        BaseClientDetails client = createBaseClient(new RandomValueStringGenerator().generate(), SECRET_TOO_LONG, Collections.singleton("client_credentials"));
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
    void testCreateClient_With_Secondary_Secret() throws Exception {
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
        assertEquals(AuditEventType.ClientCreateSuccess, abstractUaaEventCaptor.getValue().getAuditEvent().getType());
    }

    @Test
    void testClientCRUDAsAdminUser() throws Exception {
        setupAdminUserToken();
        ClientDetails client = createClient(adminUserToken, SECRET, new RandomValueStringGenerator().generate(),
                Collections.singleton("client_credentials"));
        verify(mockApplicationEventPublisher, times(2)).publishEvent(abstractUaaEventCaptor.capture());
        for (AbstractUaaEvent event : abstractUaaEventCaptor.getAllValues()) {
            assertEquals(AuditEventType.ClientCreateSuccess, event.getAuditEvent().getType());
        }

        MockHttpServletRequestBuilder getClient = get("/oauth/clients/" + client.getClientId())
                .header("Authorization", "Bearer " + adminUserToken)
                .accept(APPLICATION_JSON);
        MvcResult mvcResult = mockMvc.perform(getClient)
                .andExpect(status().isOk())
                .andReturn();
        BaseClientDetails clientDetails = JsonUtils.readValue(mvcResult.getResponse().getContentAsString(), BaseClientDetails.class);
        assertEquals(client.getClientId(), clientDetails.getClientId());

        clientDetails.setAuthorizedGrantTypes(Collections.singleton(GRANT_TYPE_AUTHORIZATION_CODE));
        MockHttpServletRequestBuilder updateClient = put("/oauth/clients/" + client.getClientId())
                .header("Authorization", "Bearer" + adminUserToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(clientDetails));
        MvcResult result = mockMvc.perform(updateClient).andExpect(status().isOk()).andReturn();
        BaseClientDetails updatedClientDetails = JsonUtils.readValue(result.getResponse().getContentAsString(), BaseClientDetails.class);
        assertEquals(client.getClientId(), updatedClientDetails.getClientId());
        assertThat(updatedClientDetails.getAuthorizedGrantTypes(), PredicateMatcher.has(m -> m.equals(GRANT_TYPE_AUTHORIZATION_CODE)));

        MockHttpServletRequestBuilder deleteClient = delete("/oauth/clients/" + client.getClientId())
                .header("Authorization", "Bearer" + adminUserToken)
                .accept(APPLICATION_JSON);
        MvcResult deleteResult = mockMvc.perform(deleteClient).andExpect(status().isOk()).andReturn();
        BaseClientDetails deletedClientDetails = JsonUtils.readValue(deleteResult.getResponse().getContentAsString(), BaseClientDetails.class);
        assertEquals(client.getClientId(), deletedClientDetails.getClientId());
    }

    @Test
    void create_client_and_check_created_by() throws Exception {
        setupAdminUserToken();

        BaseClientDetails clientDetails = createClient(Arrays.asList("password.write", "scim.write", "scim.read", "clients.write"));

        ClientMetadata clientMetadata = obtainClientMetadata(clientDetails.getClientId());
        SearchResults<Map<String, Object>> marissa = (SearchResults<Map<String, Object>>) scimUserEndpoints.findUsers("id,userName", "userName eq \"" + testUser.getUserName() + "\"", "userName", "asc", 0, 1);
        String marissaId = (String) marissa.getResources().iterator().next().get("id");
        assertEquals(marissaId, clientMetadata.getCreatedBy());

        clientDetails = createClient(Collections.singletonList("uaa.resource"));

        clientMetadata = obtainClientMetadata(clientDetails.getClientId());
        assertEquals(marissaId, clientMetadata.getCreatedBy());
    }

    @Test
    void test_Read_Restricted_Scopes() throws Exception {
        MockHttpServletRequestBuilder createClientPost = get("/oauth/clients/restricted")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON);
        mockMvc.perform(createClientPost)
                .andExpect(status().isOk())
                .andExpect(content().string(JsonUtils.writeValueAsString(new UaaScopes().getUaaScopes())));

    }

    @Test
    void testCreate_RestrictedClient_Fails() throws Exception {
        String id = new RandomValueStringGenerator().generate();
        List<String> grantTypes = Arrays.asList("client_credentials", "password");
        BaseClientDetails clientWithAuthorities = createBaseClient(id, SECRET, grantTypes, new UaaScopes().getUaaScopes(), null);
        BaseClientDetails clientWithScopes = createBaseClient(id, SECRET, grantTypes, null, new UaaScopes().getUaaScopes());

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
    void testCreate_RestrictedClient_Succeeds() throws Exception {
        String id = new RandomValueStringGenerator().generate();
        List<String> scopes = Collections.singletonList("openid");
        BaseClientDetails client = createBaseClient(id, SECRET, Arrays.asList("client_credentials", "password"), scopes, scopes);

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
    void testCreateClientsTxFailure_Secret_Too_Long() throws Exception {
        int count = 5;
        BaseClientDetails[] details = createBaseClients(count, SECRET_TOO_LONG, null);
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
    void testCreateClientsTxSuccess() throws Exception {
        int count = 5;
        BaseClientDetails[] details = createBaseClients(count, SECRET, null);
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
            assertNotNull(c);
            assertNull(c.getClientSecret());
        }
        verify(mockApplicationEventPublisher, times(count)).publishEvent(abstractUaaEventCaptor.capture());
        for (AbstractUaaEvent event : abstractUaaEventCaptor.getAllValues()) {
            assertEquals(AuditEventType.ClientCreateSuccess, event.getAuditEvent().getType());
        }
    }

    @Test
    void testCreateClientsTxDuplicateId() throws Exception {
        BaseClientDetails[] details = createBaseClients(5, SECRET, null);
        details[details.length - 1] = details[0];
        MockHttpServletRequestBuilder createClientPost = post("/oauth/clients/tx")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(details));
        mockMvc.perform(createClientPost).andExpect(status().isConflict());
        for (ClientDetails client : details) {
            assertNull(getClient(client.getClientId()));
        }
        verify(mockApplicationEventPublisher, times(0)).publishEvent(abstractUaaEventCaptor.capture());
    }

    @Test
    void test_InZone_ClientWrite_Failure_with_Min_Length_Secret() throws Exception {
        String subdomain = generator.generate();
        MockMvcUtils.IdentityZoneCreationResult result = MockMvcUtils.createOtherIdentityZoneAndReturnResult(subdomain, mockMvc, webApplicationContext, null, IdentityZoneHolder.getCurrentZoneId());
        result.getIdentityZone().getConfig().setClientSecretPolicy(new ClientSecretPolicy(7, 255, 0, 0, 0, 0, 6));
        MockMvcUtils.setZoneConfiguration(webApplicationContext, result.getIdentityZone().getId(), result.getIdentityZone().getConfig());

        String clientId = generator.generate();
        BaseClientDetails client = new BaseClientDetails(clientId, "", "openid", GRANT_TYPE_AUTHORIZATION_CODE, "", "http://sample.redirect");
        client.setClientSecret("secret");
        MockMvcUtils.createClient(mockMvc, result.getZoneAdminToken(), client, result.getIdentityZone(),
                status().isBadRequest());
    }

    @Test
    void test_InZone_ClientWrite_Failure_with_Secret_Too_Long() throws Exception {
        String subdomain = generator.generate();
        MockMvcUtils.IdentityZoneCreationResult result = MockMvcUtils.createOtherIdentityZoneAndReturnResult(subdomain, mockMvc, webApplicationContext, null, IdentityZoneHolder.getCurrentZoneId());
        result.getIdentityZone().getConfig().setClientSecretPolicy(new ClientSecretPolicy(0, 5, 0, 0, 0, 0, 6));
        MockMvcUtils.setZoneConfiguration(webApplicationContext, result.getIdentityZone().getId(), result.getIdentityZone().getConfig());

        String clientId = generator.generate();
        BaseClientDetails client = new BaseClientDetails(clientId, "", "openid", GRANT_TYPE_AUTHORIZATION_CODE, "", "http://sample.redirect");
        client.setClientSecret("secret");
        MockMvcUtils.createClient(mockMvc, result.getZoneAdminToken(), client, result.getIdentityZone(),
                status().isBadRequest());
    }

    @Test
    void test_InZone_ClientWrite_Failure_with_Secret_Requires_Uppercase_Character() throws Exception {
        String subdomain = generator.generate();
        MockMvcUtils.IdentityZoneCreationResult result = MockMvcUtils.createOtherIdentityZoneAndReturnResult(subdomain, mockMvc, webApplicationContext, null, IdentityZoneHolder.getCurrentZoneId());
        result.getIdentityZone().getConfig().setClientSecretPolicy(new ClientSecretPolicy(0, 255, 1, 0, 0, 0, 6));
        MockMvcUtils.setZoneConfiguration(webApplicationContext, result.getIdentityZone().getId(), result.getIdentityZone().getConfig());

        String clientId = generator.generate();
        BaseClientDetails client = new BaseClientDetails(clientId, "", "openid", GRANT_TYPE_AUTHORIZATION_CODE, "", "http://sample.redirect");
        client.setClientSecret("secret");
        MockMvcUtils.createClient(mockMvc, result.getZoneAdminToken(), client, result.getIdentityZone(),
                status().isBadRequest());
    }

    @Test
    void test_InZone_ClientWrite_Failure_with_Secret_Requires_Lowercase_Character() throws Exception {
        String subdomain = generator.generate();
        MockMvcUtils.IdentityZoneCreationResult result = MockMvcUtils.createOtherIdentityZoneAndReturnResult(subdomain, mockMvc, webApplicationContext, null, IdentityZoneHolder.getCurrentZoneId());
        result.getIdentityZone().getConfig().setClientSecretPolicy(new ClientSecretPolicy(0, 255, 0, 1, 0, 0, 6));
        MockMvcUtils.setZoneConfiguration(webApplicationContext, result.getIdentityZone().getId(), result.getIdentityZone().getConfig());

        String clientId = generator.generate();
        BaseClientDetails client = new BaseClientDetails(clientId, "", "openid", GRANT_TYPE_AUTHORIZATION_CODE, "", "http://sample.redirect");
        client.setClientSecret("SECRET");
        MockMvcUtils.createClient(mockMvc, result.getZoneAdminToken(), client, result.getIdentityZone(),
                status().isBadRequest());
    }

    @Test
    void test_InZone_ClientWrite_Success_with_Complex_Secret_Policy() throws Exception {
        String subdomain = generator.generate();
        MockMvcUtils.IdentityZoneCreationResult result = MockMvcUtils.createOtherIdentityZoneAndReturnResult(subdomain, mockMvc, webApplicationContext, null, IdentityZoneHolder.getCurrentZoneId());
        result.getIdentityZone().getConfig().setClientSecretPolicy(new ClientSecretPolicy(6, 255, 1, 1, 1, 1, 6));
        MockMvcUtils.setZoneConfiguration(webApplicationContext, result.getIdentityZone().getId(), result.getIdentityZone().getConfig());

        String clientId = generator.generate();
        BaseClientDetails client = new BaseClientDetails(clientId, "", "openid", GRANT_TYPE_AUTHORIZATION_CODE, "", "http://sample.redirect");
        client.setClientSecret("Secret1@");
        MockMvcUtils.createClient(mockMvc, result.getZoneAdminToken(), client, result.getIdentityZone(),
                status().isCreated());
    }

    @Test
    void test_InZone_ClientWrite_Failure_with_Secret_Requires_Special_Character() throws Exception {
        String subdomain = generator.generate();
        MockMvcUtils.IdentityZoneCreationResult result = MockMvcUtils.createOtherIdentityZoneAndReturnResult(subdomain, mockMvc, webApplicationContext, null, IdentityZoneHolder.getCurrentZoneId());
        result.getIdentityZone().getConfig().setClientSecretPolicy(new ClientSecretPolicy(0, 255, 0, 0, 0, 1, 6));
        MockMvcUtils.setZoneConfiguration(webApplicationContext, result.getIdentityZone().getId(), result.getIdentityZone().getConfig());

        String clientId = generator.generate();
        BaseClientDetails client = new BaseClientDetails(clientId, "", "openid", GRANT_TYPE_AUTHORIZATION_CODE, "", "http://sample.redirect");
        client.setClientSecret("secret");
        MockMvcUtils.createClient(mockMvc, result.getZoneAdminToken(), client, result.getIdentityZone(),
                status().isBadRequest());
    }

    @Test
    void test_InZone_ClientWrite_Failure_with_Secret_Requires_Digit() throws Exception {
        String subdomain = generator.generate();
        MockMvcUtils.IdentityZoneCreationResult result = MockMvcUtils.createOtherIdentityZoneAndReturnResult(subdomain, mockMvc, webApplicationContext, null, IdentityZoneHolder.getCurrentZoneId());
        result.getIdentityZone().getConfig().setClientSecretPolicy(new ClientSecretPolicy(0, 255, 0, 0, 1, 0, 6));
        MockMvcUtils.setZoneConfiguration(webApplicationContext, result.getIdentityZone().getId(), result.getIdentityZone().getConfig());

        String clientId = generator.generate();
        BaseClientDetails client = new BaseClientDetails(clientId, "", "openid", GRANT_TYPE_AUTHORIZATION_CODE, "", "http://sample.redirect");
        client.setClientSecret("secret");
        MockMvcUtils.createClient(mockMvc, result.getZoneAdminToken(), client, result.getIdentityZone(),
                status().isBadRequest());
    }

    @Test
    void test_InZone_ClientWrite_Using_ZonesDotAdmin() throws Exception {
        String subdomain = generator.generate();
        MockMvcUtils.IdentityZoneCreationResult result = MockMvcUtils.createOtherIdentityZoneAndReturnResult(subdomain, mockMvc, webApplicationContext, null, IdentityZoneHolder.getCurrentZoneId());
        String clientId = generator.generate();
        BaseClientDetails client = new BaseClientDetails(clientId, "", "openid", GRANT_TYPE_AUTHORIZATION_CODE, "", "http://some.redirect.url.com");
        client.setClientSecret("secret");
        MockMvcUtils.createClient(mockMvc, result.getZoneAdminToken(), client, result.getIdentityZone(),
                status().isCreated());
    }

    @Test
    void test_InZone_ClientWrite_Using_ZonesDotClientsDotAdmin() throws Exception {
        String subdomain = generator.generate();
        MockMvcUtils.IdentityZoneCreationResult result = MockMvcUtils.createOtherIdentityZoneAndReturnResult(subdomain, mockMvc, webApplicationContext, null, IdentityZoneHolder.getCurrentZoneId());
        String id = result.getIdentityZone().getId();
        String clientId = generator.generate();
        BaseClientDetails client = new BaseClientDetails(clientId, "", "", "client_credentials", "zones." + id + ".clients.admin", "http://some.redirect.url.com");
        client.setClientSecret("secret");
        client = MockMvcUtils.createClient(mockMvc, adminToken, client);
        client.setClientSecret("secret");

        String zonesClientsAdminToken = MockMvcUtils.getClientOAuthAccessToken(mockMvc, client.getClientId(), client.getClientSecret(), "zones." + id + ".clients.admin");

        BaseClientDetails newclient = new BaseClientDetails(clientId, "", "openid", GRANT_TYPE_AUTHORIZATION_CODE, "", "http://some.redirect.url.com");
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

        BaseClientDetails client = new BaseClientDetails(clientId, "", "openid", GRANT_TYPE_AUTHORIZATION_CODE, "", "http://some.redirect.url.com");
        client.setClientSecret("secret");
        BaseClientDetails createdClient = MockMvcUtils.createClient(mockMvc, adminUserToken, client,
                result.getIdentityZone(), status().isCreated());

        assertEquals(client.getClientId(), createdClient.getClientId());

        MockHttpServletRequestBuilder getClient = get("/oauth/clients/" + client.getClientId())
                .header("Authorization", "Bearer " + adminUserToken)
                .header("X-Identity-Zone-Id", zoneId)
                .accept(APPLICATION_JSON);
        MvcResult mvcResult = mockMvc.perform(getClient)
                .andExpect(status().isOk())
                .andReturn();
        BaseClientDetails clientDetails = JsonUtils.readValue(mvcResult.getResponse().getContentAsString(), BaseClientDetails.class);
        assertEquals(client.getClientId(), clientDetails.getClientId());

        clientDetails.setAuthorizedGrantTypes(Collections.singleton(GRANT_TYPE_AUTHORIZATION_CODE));
        MockHttpServletRequestBuilder updateClient = put("/oauth/clients/" + client.getClientId())
                .header("Authorization", "Bearer" + adminUserToken)
                .header("X-Identity-Zone-Id", zoneId)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(clientDetails));
        mvcResult = mockMvc.perform(updateClient).andExpect(status().isOk()).andReturn();
        BaseClientDetails updatedClientDetails = JsonUtils.readValue(mvcResult.getResponse().getContentAsString(), BaseClientDetails.class);
        assertEquals(client.getClientId(), updatedClientDetails.getClientId());
        assertThat(updatedClientDetails.getAuthorizedGrantTypes(), PredicateMatcher.has(m -> m.equals(GRANT_TYPE_AUTHORIZATION_CODE)));

        MockHttpServletRequestBuilder deleteClient = delete("/oauth/clients/" + client.getClientId())
                .header("Authorization", "Bearer" + adminUserToken)
                .header("X-Identity-Zone-Id", zoneId)
                .accept(APPLICATION_JSON);
        MvcResult deleteResult = mockMvc.perform(deleteClient).andExpect(status().isOk()).andReturn();
        BaseClientDetails deletedClientDetails = JsonUtils.readValue(deleteResult.getResponse().getContentAsString(), BaseClientDetails.class);
        assertEquals(client.getClientId(), deletedClientDetails.getClientId());
    }

    @Test
    void test_InZone_ClientRead_Using_ZonesDotClientsDotAdmin() throws Exception {
        String subdomain = generator.generate();
        MockMvcUtils.IdentityZoneCreationResult result = MockMvcUtils.createOtherIdentityZoneAndReturnResult(subdomain, mockMvc, webApplicationContext, null, IdentityZoneHolder.getCurrentZoneId());
        String id = result.getIdentityZone().getId();
        String clientId = generator.generate();
        BaseClientDetails client = new BaseClientDetails(clientId, "", "", "client_credentials", "zones." + id + ".clients.admin", "http://some.redirect.url.com");
        client.setClientSecret("secret");
        client = MockMvcUtils.createClient(mockMvc, adminToken, client);
        client.setClientSecret("secret");

        String zonesClientsAdminToken = MockMvcUtils.getClientOAuthAccessToken(mockMvc, client.getClientId(), client.getClientSecret(), "zones." + id + ".clients.admin");

        BaseClientDetails newclient = new BaseClientDetails(clientId, "", "openid", GRANT_TYPE_AUTHORIZATION_CODE, "", "http://some.redirect.url.com");
        newclient.setClientSecret("secret");
        MockMvcUtils.createClient(mockMvc, zonesClientsAdminToken, newclient,
                result.getIdentityZone(), status().isCreated());
    }

    @Test
    void test_InZone_ClientRead_Using_ZonesDotClientsDotRead() throws Exception {
        String subdomain = generator.generate();
        MockMvcUtils.IdentityZoneCreationResult result = MockMvcUtils.createOtherIdentityZoneAndReturnResult(subdomain, mockMvc, webApplicationContext, null, IdentityZoneHolder.getCurrentZoneId());
        String id = result.getIdentityZone().getId();
        String clientId = generator.generate();
        BaseClientDetails client = new BaseClientDetails(clientId, "", "", "client_credentials", "zones." + id + ".clients.read", "http://some.redirect.url.com");
        client.setClientSecret("secret");
        client = MockMvcUtils.createClient(mockMvc, adminToken, client);
        client.setClientSecret("secret");

        String zonesClientsReadToken = MockMvcUtils.getClientOAuthAccessToken(mockMvc, client.getClientId(), client.getClientSecret(), "zones." + id + ".clients.read");

        BaseClientDetails newclient = new BaseClientDetails(clientId, "", "openid", GRANT_TYPE_AUTHORIZATION_CODE, "", "http://some.redirect.url.com");
        newclient.setClientSecret("secret");
        MockMvcUtils.createClient(mockMvc, result.getZoneAdminToken(), newclient,
                result.getIdentityZone(), status().isCreated());

        MockMvcUtils.getClient(mockMvc, zonesClientsReadToken, newclient.getClientId(), result.getIdentityZone());
    }

    @Test
    void testCreateClientsTxClientCredentialsWithoutSecret() throws Exception {
        BaseClientDetails[] details = createBaseClients(5, null, null);
        details[details.length - 1].setAuthorizedGrantTypes(StringUtils.commaDelimitedListToSet("client_credentials"));
        details[details.length - 1].setClientSecret(null);
        MockHttpServletRequestBuilder createClientPost = post("/oauth/clients/tx")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(details));
        mockMvc.perform(createClientPost).andExpect(status().isBadRequest());
        for (ClientDetails client : details) {
            assertNull(getClient(client.getClientId()));
        }
        verify(mockApplicationEventPublisher, times(0)).publishEvent(abstractUaaEventCaptor.capture());
    }

    @Test
    void testUpdateClientsTxSuccess() throws Exception {
        int count = 5;
        BaseClientDetails[] details = new BaseClientDetails[count];
        for (int i = 0; i < details.length; i++) {
            details[i] = (BaseClientDetails) createClient(adminToken, null, SECRET, null);
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
            assertNotNull(getClient(client.getClientId()));
            assertEquals(Integer.valueOf(120), client.getRefreshTokenValiditySeconds());
        }
        //create and then update events
        verify(mockApplicationEventPublisher, times(count * 2)).publishEvent(abstractUaaEventCaptor.capture());
        int index = 0;
        for (AbstractUaaEvent event : abstractUaaEventCaptor.getAllValues()) {
            if (index < count) {
                assertEquals(AuditEventType.ClientCreateSuccess, event.getAuditEvent().getType());
            } else {
                assertEquals(AuditEventType.ClientUpdateSuccess, event.getAuditEvent().getType());
            }
            index++;
        }
    }

    @Test
    void testUpdateClientsTxInvalidId() throws Exception {
        int count = 5;
        BaseClientDetails[] details = new BaseClientDetails[count];
        for (int i = 0; i < details.length; i++) {
            details[i] = (BaseClientDetails) createClient(adminToken, null, SECRET, null);
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
            assertNotNull(c);
            assertNull(c.getClientSecret());
            assertNull(c.getRefreshTokenValiditySeconds());
        }
        //create and then update events
        verify(mockApplicationEventPublisher, times(count)).publishEvent(abstractUaaEventCaptor.capture());
    }

    @Test
    void testDeleteClientsTxSuccess() throws Exception {
        int count = 5;
        BaseClientDetails[] details = new BaseClientDetails[count];
        for (int i = 0; i < details.length; i++) {
            details[i] = (BaseClientDetails) createClient(adminToken, null, SECRET, null);
        }
        MockHttpServletRequestBuilder deleteClientsPost = post("/oauth/clients/tx/delete")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(details));
        ResultActions result = mockMvc.perform(deleteClientsPost);
        result.andExpect(status().isOk());
        for (ClientDetails client : details) {
            assertNull(getClient(client.getClientId()));
        }
        //create and then update events
        verify(mockApplicationEventPublisher, times(count * 2)).publishEvent(abstractUaaEventCaptor.capture());
        int index = 0;
        for (AbstractUaaEvent event : abstractUaaEventCaptor.getAllValues()) {
            if (index < count) {
                assertEquals(AuditEventType.ClientCreateSuccess, event.getAuditEvent().getType());
            } else {
                assertEquals(AuditEventType.ClientDeleteSuccess, event.getAuditEvent().getType());
            }
            index++;
        }
    }

    @Test
    void testDeleteClientsTxRollbackInvalidId() throws Exception {
        int count = 5;
        BaseClientDetails[] details = new BaseClientDetails[count];
        for (int i = 0; i < details.length; i++) {
            details[i] = (BaseClientDetails) createClient(adminToken, null, SECRET, null);
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
            assertNotNull(c);
            assertNull(c.getClientSecret());
            assertNull(c.getRefreshTokenValiditySeconds());
        }
        verify(mockApplicationEventPublisher, times(count)).publishEvent(abstractUaaEventCaptor.capture());
    }

    @Test
    void testAddUpdateDeleteClientsTxSuccess() throws Exception {
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
        for (int i = (count * 2); i < (count * 3); i++) {
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
            assertNotNull(c);
            assertEquals(Integer.valueOf(120), c.getRefreshTokenValiditySeconds());

        }
        for (int i = count; i < (count * 2); i++) {
            ClientDetails c = getClient(details[i].getClientId());
            assertNull(c);
        }
        for (int i = (count * 2); i < (count * 3); i++) {
            ClientDetails c = getClient(details[i].getClientId());
            assertNotNull(c);
            assertNull(c.getRefreshTokenValiditySeconds());
        }
        verify(mockApplicationEventPublisher, times(count * 5)).publishEvent(abstractUaaEventCaptor.capture());
        int index = 0;
        for (AbstractUaaEvent event : abstractUaaEventCaptor.getAllValues()) {
            int swit = index / count;
            switch (swit) {
                case 0:
                case 1:
                case 4: {
                    //1-10 and 21-25 events are create
                    assertEquals(AuditEventType.ClientCreateSuccess, event.getAuditEvent().getType());
                    assertEquals(ClientCreateEvent.class, event.getClass());
                    assertEquals(details[index < 10 ? index : (index - count * 2)].getClientId(), event.getAuditEvent().getPrincipalId());
                    break;
                }
                case 2: {
                    //the 11-15 events are update
                    assertEquals(AuditEventType.ClientUpdateSuccess, event.getAuditEvent().getType());
                    assertEquals(ClientUpdateEvent.class, event.getClass());
                    assertEquals(details[index - (count * 2)].getClientId(), event.getAuditEvent().getPrincipalId());
                    break;
                }
                case 3: {
                    //the 16-20 events are deletes
                    assertEquals(AuditEventType.ClientDeleteSuccess, event.getAuditEvent().getType());
                    assertEquals(ClientDeleteEvent.class, event.getClass());
                    assertEquals(details[index - count * 2].getClientId(), event.getAuditEvent().getPrincipalId());
                    break;
                }
            }
            index++;
        }
    }

    @Test
    void testAddUpdateDeleteClientsTxDeleteUnsuccessfulRollback() throws Exception {
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
                testPassword,
                "oauth.approvals");
        addApprovals(userToken, details[0].getClientId());
        Approval[] approvals = getApprovals(details[0].getClientId());
        assertEquals(3, approvals.length);


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
            assertNotNull(c);
            assertNull(c.getRefreshTokenValiditySeconds());

        }
        for (int i = 5; i < 10; i++) {
            ClientDetails c = getClient(details[i].getClientId());
            assertNotNull(c);
        }
        for (int i = 10; i < 15; i++) {
            ClientDetails c = getClient(details[i].getClientId());
            assertNull(c);
        }
        approvals = getApprovals(details[0].getClientId());
        assertEquals(3, approvals.length);
    }

    @Test
    void testApprovalsAreDeleted() throws Exception {
        ClientDetails details = createClient(adminToken, new RandomValueStringGenerator().generate(),
                SECRET, Collections.singleton("password"));
        String userToken = testClient.getUserOAuthAccessToken(
                details.getClientId(),
                "secret",
                testUser.getUserName(),
                testPassword,
                "oauth.approvals");
        Approval[] approvals = getApprovals(details.getClientId());
        assertEquals(0, approvals.length);
        addApprovals(userToken, details.getClientId());
        approvals = getApprovals(details.getClientId());
        assertEquals(3, approvals.length);

        MockHttpServletRequestBuilder deleteClientsPost = post("/oauth/clients/tx/delete")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(new ClientDetails[]{details}));
        ResultActions result = mockMvc.perform(deleteClientsPost);
        result.andExpect(status().isOk());


        ClientDetailsModification[] deleted = (ClientDetailsModification[]) arrayFromString(result.andReturn().getResponse().getContentAsString(), ClientDetailsModification[].class);
        assertTrue(deleted[0].isApprovalsDeleted());
        verify(mockApplicationEventPublisher, times(2)).publishEvent(abstractUaaEventCaptor.capture());

        approvals = getApprovals(details.getClientId());
        assertEquals(0, approvals.length);
    }

    @Test
    void testApprovalsAreDeleted2() throws Exception {
        ClientDetails details = createClient(adminToken, new RandomValueStringGenerator().generate(),
                SECRET, Collections.singleton("password"));
        String userToken = testClient.getUserOAuthAccessToken(
                details.getClientId(),
                "secret",
                testUser.getUserName(),
                testPassword,
                "oauth.approvals");
        Approval[] approvals = getApprovals(details.getClientId());
        assertEquals(0, approvals.length);
        addApprovals(userToken, details.getClientId());
        approvals = getApprovals(details.getClientId());
        assertEquals(3, approvals.length);

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
                testPassword,
                "oauth.approvals");

        approvals = getApprovals(details.getClientId());
        assertEquals(0, approvals.length);
    }

    @Test
    void testModifyApprovalsAreDeleted() throws Exception {
        ClientDetails details = createClient(adminToken, new RandomValueStringGenerator().generate(),
                SECRET, Collections.singleton("password"));
        ((ClientDetailsModification) details).setAction(ClientDetailsModification.DELETE);
        String userToken = testClient.getUserOAuthAccessToken(
                details.getClientId(),
                "secret",
                testUser.getUserName(),
                testPassword,
                "oauth.approvals");
        Approval[] approvals = getApprovals(details.getClientId());
        assertEquals(0, approvals.length);
        addApprovals(userToken, details.getClientId());
        approvals = getApprovals(details.getClientId());
        assertEquals(3, approvals.length);

        MockHttpServletRequestBuilder deleteClientsPost = post("/oauth/clients/tx/modify")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(new ClientDetails[]{details}));
        ResultActions result = mockMvc.perform(deleteClientsPost);
        result.andExpect(status().isOk());
        ClientDetailsModification[] deleted = (ClientDetailsModification[]) arrayFromString(result.andReturn().getResponse().getContentAsString(), ClientDetailsModification[].class);
        assertTrue(deleted[0].isApprovalsDeleted());
        verify(mockApplicationEventPublisher, times(2)).publishEvent(abstractUaaEventCaptor.capture());

        ClientDetails approvalsClient = createApprovalsLoginClient(adminToken);
        String loginToken = testClient.getUserOAuthAccessToken(
                approvalsClient.getClientId(),
                "secret",
                testUser.getUserName(),
                testPassword,
                "oauth.approvals");
        approvals = getApprovals(details.getClientId());
        assertEquals(0, approvals.length);
    }

    @Test
    void testSecretChangeTxApprovalsNotDeleted() throws Exception {
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
                    testPassword,
                    "oauth.approvals");
            addApprovals(userToken, c.getClientId());
        }

        //verify approvals to the client
        for (ClientDetailsModification c : clients) {
            String userToken = testClient.getUserOAuthAccessToken(
                    c.getClientId(),
                    "secret",
                    testUser.getUserName(),
                    testPassword,
                    "oauth.approvals");
            assertEquals(3, getApprovals(c.getClientId()).length);
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
                    testPassword,
                    "oauth.approvals");
            assertEquals(3, getApprovals(c.getClientId()).length);
            assertFalse(c.isApprovalsDeleted());
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
    void testSecretChangeEvent() throws Exception {
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
        assertEquals(SecretChangeEvent.class, abstractUaaEventCaptor.getValue().getClass());
        SecretChangeEvent event = (SecretChangeEvent) abstractUaaEventCaptor.getValue();
        assertEquals(id, event.getAuditEvent().getPrincipalId());
    }

    @Test
    void testAddNewClientSecret() throws Exception {
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
        assertEquals("ok", actionResult.getStatus());
        assertEquals("Secret is added", actionResult.getMessage());

        verify(mockApplicationEventPublisher, times(2)).publishEvent(abstractUaaEventCaptor.capture());
        assertEquals(SecretChangeEvent.class, abstractUaaEventCaptor.getValue().getClass());
        SecretChangeEvent event = (SecretChangeEvent) abstractUaaEventCaptor.getValue();
        assertEquals(id, event.getAuditEvent().getPrincipalId());
    }

    @Test
    void testAddMoreThanTwoClientSecret() throws Exception {
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

        UaaException invalidClientDetailsException = JsonUtils.readValue(response.getContentAsString(), UaaException.class);
        assertEquals("invalid_client", invalidClientDetailsException.getErrorCode());
        assertEquals("client secret is either empty or client already has two secrets.", invalidClientDetailsException.getMessage());
        verify(mockApplicationEventPublisher, times(3)).publishEvent(abstractUaaEventCaptor.capture());
        assertEquals(SecretFailureEvent.class, abstractUaaEventCaptor.getValue().getClass());
        SecretFailureEvent event = (SecretFailureEvent) abstractUaaEventCaptor.getValue();
        assertEquals(id, event.getAuditEvent().getPrincipalId());
    }

    @Test
    void testDeleteClientSecret() throws Exception {
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
        assertNotNull(actionResult);
        assertEquals("ok", actionResult.getStatus());
        assertEquals("Secret is deleted", actionResult.getMessage());

        verify(mockApplicationEventPublisher, times(3)).publishEvent(abstractUaaEventCaptor.capture());
        assertEquals(SecretChangeEvent.class, abstractUaaEventCaptor.getValue().getClass());
        SecretChangeEvent event = (SecretChangeEvent) abstractUaaEventCaptor.getValue();
        assertEquals(id, event.getAuditEvent().getPrincipalId());
    }

    @Test
    void testDeleteClientSecretForClientWithOneSecret() throws Exception {
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

        UaaException invalidClientDetailsException = JsonUtils.readValue(response.getContentAsString(), UaaException.class);
        assertEquals("invalid_client", invalidClientDetailsException.getErrorCode());
        assertEquals("client secret is either empty or client has only one secret.", invalidClientDetailsException.getMessage());

        verify(mockApplicationEventPublisher, times(2)).publishEvent(abstractUaaEventCaptor.capture());
        assertEquals(SecretFailureEvent.class, abstractUaaEventCaptor.getValue().getClass());
        SecretFailureEvent event = (SecretFailureEvent) abstractUaaEventCaptor.getValue();
        assertEquals(id, event.getAuditEvent().getPrincipalId());
    }

    @Test
    void testSecretChange_UsingAdminClientToken() throws Exception {
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
    void testSecretChange_UsingClientAdminToken() throws Exception {
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
    void testUnsuccessfulSecretChangeEvent() throws Exception {

        List<String> scopes = Arrays.asList("oauth.approvals", "clients.secret");
        BaseClientDetails client = createBaseClient(null, SECRET, Arrays.asList("password", "client_credentials"), scopes, scopes);
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
        assertEquals(SecretFailureEvent.class, abstractUaaEventCaptor.getValue().getClass());
        SecretFailureEvent event = (SecretFailureEvent) abstractUaaEventCaptor.getValue();
        assertEquals(client.getClientId(), event.getAuditEvent().getPrincipalId());
    }

    @Test
    void testSecretChangeModifyTxApprovalsDeleted() throws Exception {
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
                    testPassword,
                    "oauth.approvals");
            addApprovals(userToken, c.getClientId());
        }

        //verify approvals to the client
        for (ClientDetailsModification c : clients) {
            String userToken = testClient.getUserOAuthAccessToken(
                    c.getClientId(),
                    "secret",
                    testUser.getUserName(),
                    testPassword,
                    "oauth.approvals");
            assertEquals(3, getApprovals(c.getClientId()).length);
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
                    testPassword,
                    "oauth.approvals");
            assertEquals(0, getApprovals(c.getClientId()).length);
            assertTrue(c.isApprovalsDeleted());
        }

        //verify(mockApplicationEventPublisher, times(count*3)).publishEvent(abstractUaaEventCaptor.capture());
        verify(mockApplicationEventPublisher, times(12)).publishEvent(abstractUaaEventCaptor.capture());
        int index = 0;
        for (AbstractUaaEvent event : abstractUaaEventCaptor.getAllValues()) {
            if (index < count) {
                assertEquals(AuditEventType.ClientCreateSuccess, event.getAuditEvent().getType());
            } else {
                int swit = index % 3;
                if (swit == 0) {
                    assertEquals(AuditEventType.ClientUpdateSuccess, event.getAuditEvent().getType());
                } else if (swit == 1) {
                    assertEquals(AuditEventType.SecretChangeSuccess, event.getAuditEvent().getType());
                } else {
                    assertEquals(AuditEventType.ClientApprovalsDeleted, event.getAuditEvent().getType());
                    assertEquals(ClientApprovalsDeletedEvent.class, event.getClass());
                }
            }

            index++;
        }
    }

    @Test
    void testSecretChangeModifyTxApprovalsNotDeleted() throws Exception {
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
                    testPassword,
                    "oauth.approvals");
            addApprovals(userToken, c.getClientId());
        }

        //verify approvals to the client
        for (ClientDetailsModification c : clients) {
            String userToken = testClient.getUserOAuthAccessToken(
                    c.getClientId(),
                    "secret",
                    testUser.getUserName(),
                    testPassword,
                    "oauth.approvals");
            assertEquals(3, getApprovals(c.getClientId()).length);
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
            assertFalse(c.isApprovalsDeleted());
            String userToken = testClient.getUserOAuthAccessToken(
                    c.getClientId(),
                    "secret",
                    testUser.getUserName(),
                    testPassword,
                    "oauth.approvals");
            assertEquals(3, getApprovals(c.getClientId()).length);
        }
    }

    @Test
    void testClientsAdminPermissions() throws Exception {
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
    void testNonClientsAdminPermissions() throws Exception {
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
    void testCreateAsAdminPermissions() throws Exception {
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
    void testCreateAsReadPermissions() throws Exception {
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
    void testCreateAsWritePermissions() throws Exception {
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
    void testGetClientDetailsSortedByLastModified() throws Exception {

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

        Collection<BaseClientDetails> clientDetails = JsonUtils.readValue(body, new TypeReference<SearchResults<BaseClientDetails>>() {
        }).getResources();

        assertNotNull(clientDetails);

        Date lastDate = null;

        for (ClientDetails clientDetail : clientDetails) {
            assertTrue(clientDetail.getAdditionalInformation().containsKey("lastModified"));

            Date currentDate = JsonUtils.convertValue(clientDetail.getAdditionalInformation().get("lastModified"), Date.class);

            if (lastDate != null) {
                assertTrue(currentDate.getTime() <= lastDate.getTime());
            }

            lastDate = currentDate;
        }
    }

    @Test
    void testGetClientsLargerThanMax_whenCountParamIsProvided() throws Exception {
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


        SearchResults<BaseClientDetails> clientDetailsSearchResults = JsonUtils.readValue(body, new TypeReference<SearchResults<BaseClientDetails>>() {
        });

        assertThat(clientDetailsSearchResults.getItemsPerPage(), is(clientMaxCount));
        assertThat(clientDetailsSearchResults.getTotalResults(), greaterThan(6));
        assertThat(clientDetailsSearchResults.getStartIndex(), is(1));
        assertThat(clientDetailsSearchResults.getResources(), hasSize(clientMaxCount));
    }

    @Test
    void testGetClientsLargerThanMax_whenNoCountParamIsProvided() throws Exception {
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


        SearchResults<BaseClientDetails> clientDetailsSearchResults = JsonUtils.readValue(body, new TypeReference<SearchResults<BaseClientDetails>>() {
        });

        assertThat(clientDetailsSearchResults.getItemsPerPage(), is(clientMaxCount));
        assertThat(clientDetailsSearchResults.getTotalResults(), greaterThan(numOfClientsCreated));
        assertThat(clientDetailsSearchResults.getStartIndex(), is(1));
        assertThat(clientDetailsSearchResults.getResources(), hasSize(clientMaxCount));
    }

    @Test
    void testClientWithDotInID() throws Exception {
        createClient(adminToken, "testclient", SECRET, Collections.singleton("client_credentials"));
        ClientDetails detailsv2 = createClient(adminToken, "testclient.v2", SECRET,
                Collections.singleton("client_credentials"));
        assertEquals("testclient.v2", detailsv2.getClientId());
    }

    @Test
    void testPutClientModifyAuthorities() throws Exception {
        ClientDetails client = createClient(adminToken, "testClientForModifyAuthorities",
                SECRET, Collections.singleton("client_credentials"));

        BaseClientDetails modified = new BaseClientDetails(client);
        modified.setAuthorities(Collections.singleton((GrantedAuthority) () -> "newAuthority"));

        MockHttpServletRequestBuilder put = put("/oauth/clients/" + client.getClientId())
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(modified));
        mockMvc.perform(put).andExpect(status().isOk()).andReturn();

        client = getClient(client.getClientId());
        assertThat(client.getAuthorities(), iterableWithSize(1));
        GrantedAuthority authority = Iterables.get(client.getAuthorities(), 0);
        assertEquals("newAuthority", authority.getAuthority());
    }

    @Test
    void testPutClientModifyAccessTokenValidity() throws Exception {
        ClientDetails client = createClient(adminToken, "testClientForModifyAccessTokenValidity",
                SECRET, Collections.singleton("client_credentials"));

        BaseClientDetails modified = new BaseClientDetails(client);
        modified.setAccessTokenValiditySeconds(73);

        MockHttpServletRequestBuilder put = put("/oauth/clients/" + client.getClientId())
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(modified));
        mockMvc.perform(put).andExpect(status().isOk()).andReturn();

        client = getClient(client.getClientId());
        assertThat(client.getAccessTokenValiditySeconds(), is(73));
    }

    @Test
    void testPutClientModifyName() throws Exception {
        ClientDetails client = createClient(adminToken, "testClientForModifyName",
                SECRET, Collections.singleton("client_credentials"));

        Map<String, Object> requestBody = JsonUtils.readValue(JsonUtils.writeValueAsString(new BaseClientDetails(client)), new TypeReference<Map<String, Object>>() {
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
        assertThat(map, hasEntry(is("name"), PredicateMatcher.is(value -> value.equals("New Client Name"))));

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
        assertThat(client.getAdditionalInformation(), hasEntry(is("name"), PredicateMatcher.is(value -> value.equals("New Client Name"))));
    }

    private BaseClientDetails createClient(List<String> authorities) throws Exception {
        String clientId = generator.generate().toLowerCase();
        List<String> scopes = Arrays.asList("foo", "bar", "oauth.approvals");
        ClientDetailsModification client = createBaseClient(clientId, SECRET, Collections.singleton("client_credentials"), authorities, scopes);
        MockHttpServletRequestBuilder createClientPost = post("/oauth/clients")
                .header("Authorization", "Bearer " + adminUserToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(client));
        ResultActions createResult = mockMvc.perform(createClientPost).andExpect(status().isCreated());
        return JsonUtils.readValue(createResult.andReturn().getResponse().getContentAsString(), BaseClientDetails.class);
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
        String marissaId = (String) marissa.getResources().iterator().next().get("id");

        //add marissa to uaa.admin
        SearchResults<Map<String, Object>> uaaAdmin = (SearchResults<Map<String, Object>>) scimGroupEndpoints.listGroups("id,displayName", "displayName eq \"uaa.admin\"", "displayName", "asc", 1, 1);
        String groupId = (String) uaaAdmin.getResources().iterator().next().get("id");
        ScimGroup group = scimGroupEndpoints.getGroup(groupId, mockResponse);
        ScimGroupMember gm = new ScimGroupMember(marissaId, ScimGroupMember.Type.USER);
        group.getMembers().add(gm);
        scimGroupEndpoints.updateGroup(group, groupId, String.valueOf(group.getVersion()), mockResponse);

        //add marissa to clients.write
        uaaAdmin = (SearchResults<Map<String, Object>>) scimGroupEndpoints.listGroups("id,displayName", "displayName eq \"clients.write\"", "displayName", "asc", 1, 1);
        groupId = (String) uaaAdmin.getResources().iterator().next().get("id");
        group = scimGroupEndpoints.getGroup(groupId, mockResponse);
        gm = new ScimGroupMember(marissaId, ScimGroupMember.Type.USER);
        group.getMembers().add(gm);
        scimGroupEndpoints.updateGroup(group, groupId, String.valueOf(group.getVersion()), mockResponse);

        //add marissa to clients.read
        uaaAdmin = (SearchResults<Map<String, Object>>) scimGroupEndpoints.listGroups("id,displayName", "displayName eq \"clients.read\"", "displayName", "asc", 1, 1);
        groupId = (String) uaaAdmin.getResources().iterator().next().get("id");
        group = scimGroupEndpoints.getGroup(groupId, mockResponse);
        gm = new ScimGroupMember(marissaId, ScimGroupMember.Type.USER);
        group.getMembers().add(gm);
        scimGroupEndpoints.updateGroup(group, groupId, String.valueOf(group.getVersion()), mockResponse);

        ClientDetails adminClient = createAdminClient(adminToken);

        adminUserToken = testClient.getUserOAuthAccessToken(adminClient.getClientId(),
                "secret",
                testUser.getUserName(),
                testPassword,
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
        BaseClientDetails client = createBaseClient(id, clientSecret, grantTypes);
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
        BaseClientDetails client = createBaseClient(null, SECRET, Arrays.asList("password", "client_credentials"), scopes, scopes);
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
        BaseClientDetails client = createBaseClient(null, SECRET, Arrays.asList("password", "client_credentials"), scopes, scopes);
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
        BaseClientDetails client = createBaseClient(null, SECRET, Arrays.asList("password", "client_credentials"), scopes, scopes);

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
        BaseClientDetails client = createBaseClient(null, SECRET, Arrays.asList("password", "client_credentials"), scopes, scopes);

        MockHttpServletRequestBuilder createClientPost = post("/oauth/clients")
                .header("Authorization", "Bearer " + token)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(client));
        mockMvc.perform(createClientPost).andExpect(status().isCreated());
        return getClient(client.getClientId());
    }

}
