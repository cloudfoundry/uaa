package org.cloudfoundry.identity.uaa.mock.clients;

import com.fasterxml.jackson.core.type.TypeReference;
import com.google.common.collect.Iterables;
import org.cloudfoundry.identity.uaa.approval.Approval;
import org.cloudfoundry.identity.uaa.approval.Approval.ApprovalStatus;
import org.cloudfoundry.identity.uaa.approval.JdbcApprovalStore;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.audit.event.AbstractUaaEvent;
import org.cloudfoundry.identity.uaa.client.ClientMetadata;
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
import org.cloudfoundry.identity.uaa.oauth.client.ClientDetailsModification;
import org.cloudfoundry.identity.uaa.oauth.client.SecretChangeRequest;
import org.cloudfoundry.identity.uaa.resources.ActionResult;
import org.cloudfoundry.identity.uaa.resources.SearchResults;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.endpoints.ScimGroupEndpoints;
import org.cloudfoundry.identity.uaa.scim.endpoints.ScimUserEndpoints;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.PredicateMatcher;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletResponse;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.mock.util.ClientDetailsHelper.arrayFromString;
import static org.cloudfoundry.identity.uaa.mock.util.ClientDetailsHelper.clientArrayFromString;
import static org.cloudfoundry.identity.uaa.oauth.client.SecretChangeRequest.ChangeMode.ADD;
import static org.cloudfoundry.identity.uaa.oauth.client.SecretChangeRequest.ChangeMode.DELETE;
import static org.hamcrest.Matchers.hasEntry;
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
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class ClientAdminEndpointsMockMvcTests extends AdminClientCreator {

    private String adminUserToken = null;
    private ScimUserEndpoints scimUserEndpoints = null;
    private ScimGroupEndpoints scimGroupEndpoints = null;
    private ApplicationEventPublisher applicationEventPublisher = null;
    private ApplicationEventPublisher originalApplicationEventPublisher = null;
    private ArgumentCaptor<AbstractUaaEvent> captor = null;
    private ScimUser testUser;
    private String testPassword;
    private RandomValueStringGenerator generator  = new RandomValueStringGenerator(7);

    @Before
    public void createCaptor() throws Exception {
        applicationEventPublisher = mock(ApplicationEventPublisher.class);
        ClientAdminEventPublisher eventPublisher = (ClientAdminEventPublisher) getWebApplicationContext().getBean("clientAdminEventPublisher");
        originalApplicationEventPublisher = eventPublisher.getPublisher();
        eventPublisher.setApplicationEventPublisher(applicationEventPublisher);
        captor = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        scimUserEndpoints = getWebApplicationContext().getBean(ScimUserEndpoints.class);
        scimGroupEndpoints = getWebApplicationContext().getBean(ScimGroupEndpoints.class);
        testPassword = "password";
        String username = new RandomValueStringGenerator().generate() + "@test.org";
        testUser = new ScimUser(null, username, "givenname","familyname");
        testUser.setPrimaryEmail(username);
        testUser.setPassword(testPassword);
        testUser = MockMvcUtils.utils().createUser(getMockMvc(), adminToken, testUser);
        testUser.setPassword(testPassword);

        applicationEventPublisher = mock(ApplicationEventPublisher.class);
        eventPublisher.setApplicationEventPublisher(applicationEventPublisher);
        captor = ArgumentCaptor.forClass(AbstractUaaEvent.class);
    }

    @After
    public void restorePublisher() throws Exception {
        ClientAdminEventPublisher eventPublisher = (ClientAdminEventPublisher) getWebApplicationContext().getBean("clientAdminEventPublisher");
        eventPublisher.setApplicationEventPublisher(originalApplicationEventPublisher);
    }

    private void setupAdminUserToken() throws Exception {
        HttpServletResponse mockResponse = mock(HttpServletResponse.class);


        SearchResults<Map<String, Object>> marissa = (SearchResults<Map<String, Object>>)scimUserEndpoints.findUsers("id,userName", "userName eq \"" + testUser.getUserName() + "\"", "userName", "asc", 0, 1);
        String marissaId = (String)marissa.getResources().iterator().next().get("id");

        //add marissa to uaa.admin
        SearchResults<Map<String, Object>> uaaAdmin = (SearchResults<Map<String, Object>>) scimGroupEndpoints.listGroups("id,displayName", "displayName eq \"uaa.admin\"", "displayName", "asc", 1, 1);
        String groupId = (String)uaaAdmin.getResources().iterator().next().get("id");
        ScimGroup group = scimGroupEndpoints.getGroup(groupId, mockResponse);
        ScimGroupMember gm = new ScimGroupMember(marissaId, ScimGroupMember.Type.USER, Arrays.asList(ScimGroupMember.Role.MEMBER));
        group.getMembers().add(gm);
        scimGroupEndpoints.updateGroup(group, groupId, String.valueOf(group.getVersion()), mockResponse);

        //add marissa to clients.write
        uaaAdmin = (SearchResults<Map<String, Object>>) scimGroupEndpoints.listGroups("id,displayName", "displayName eq \"clients.write\"", "displayName", "asc", 1, 1);
        groupId = (String)uaaAdmin.getResources().iterator().next().get("id");
        group = scimGroupEndpoints.getGroup(groupId, mockResponse);
        gm = new ScimGroupMember(marissaId, ScimGroupMember.Type.USER, Arrays.asList(ScimGroupMember.Role.MEMBER));
        group.getMembers().add(gm);
        scimGroupEndpoints.updateGroup(group, groupId, String.valueOf(group.getVersion()), mockResponse);

        //add marissa to clients.read
        uaaAdmin = (SearchResults<Map<String, Object>>) scimGroupEndpoints.listGroups("id,displayName", "displayName eq \"clients.read\"", "displayName", "asc", 1, 1);
        groupId = (String)uaaAdmin.getResources().iterator().next().get("id");
        group = scimGroupEndpoints.getGroup(groupId, mockResponse);
        gm = new ScimGroupMember(marissaId, ScimGroupMember.Type.USER, Arrays.asList(ScimGroupMember.Role.MEMBER));
        group.getMembers().add(gm);
        scimGroupEndpoints.updateGroup(group, groupId, String.valueOf(group.getVersion()), mockResponse);

        ClientDetails adminClient = createAdminClient(adminToken);

        adminUserToken = testClient.getUserOAuthAccessToken(adminClient.getClientId(),
            "secret",
            testUser.getUserName(),
            testPassword,
            "uaa.admin");
    }

    @Test
    public void testCreateClient() throws Exception {
        ClientDetails client = createClient(adminToken, new RandomValueStringGenerator().generate(), Collections.singleton("client_credentials"));
        verify(applicationEventPublisher, times(1)).publishEvent(captor.capture());
        assertEquals(AuditEventType.ClientCreateSuccess, captor.getValue().getAuditEvent().getType());
        assertEquals(makeClientName(client.getClientId()), client.getAdditionalInformation().get("name"));
    }

    @Test
    public void testCreateClientWithInvalidRedirectUrl() throws Exception {
        BaseClientDetails client = createBaseClient(new RandomValueStringGenerator().generate(),Collections.singleton("implicit"));
        client.setRegisteredRedirectUri(Collections.singleton("*/**"));
        MockHttpServletRequestBuilder createClientPost = post("/oauth/clients")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(toString(client));
        MvcResult mvcResult = getMockMvc().perform(createClientPost).andExpect(status().isBadRequest()).andReturn();
        verify(applicationEventPublisher, times(0)).publishEvent(captor.capture());
    }

    @Test
    public void testClientCRUDAsAdminUser() throws Exception {
        setupAdminUserToken();
        ClientDetails client = createClient(adminUserToken, new RandomValueStringGenerator().generate(), Collections.singleton("client_credentials"));
        verify(applicationEventPublisher, times(2)).publishEvent(captor.capture());
        for (AbstractUaaEvent event : captor.getAllValues()) {
            assertEquals(AuditEventType.ClientCreateSuccess, event.getAuditEvent().getType());
        }

        MockHttpServletRequestBuilder getClient = get("/oauth/clients/" + client.getClientId())
                .header("Authorization", "Bearer " + adminUserToken)
                .accept(APPLICATION_JSON);
        MvcResult mvcResult = getMockMvc().perform(getClient)
                .andExpect(status().isOk())
                .andReturn();
        BaseClientDetails clientDetails = JsonUtils.readValue(mvcResult.getResponse().getContentAsString(), BaseClientDetails.class);
        assertEquals(client.getClientId(), clientDetails.getClientId());

        clientDetails.setAuthorizedGrantTypes(Collections.singleton("authorization_code"));
        MockHttpServletRequestBuilder updateClient = put("/oauth/clients/" + client.getClientId())
                .header("Authorization", "Bearer" + adminUserToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(clientDetails));
        MvcResult result = getMockMvc().perform(updateClient).andExpect(status().isOk()).andReturn();
        BaseClientDetails updatedClientDetails = JsonUtils.readValue(result.getResponse().getContentAsString(), BaseClientDetails.class);
        assertEquals(client.getClientId(), updatedClientDetails.getClientId());
        assertThat(updatedClientDetails.getAuthorizedGrantTypes(), PredicateMatcher.<String>has(m -> m.equals("authorization_code")));

        MockHttpServletRequestBuilder deleteClient = delete("/oauth/clients/" + client.getClientId())
                .header("Authorization", "Bearer" + adminUserToken)
                .accept(APPLICATION_JSON);
        MvcResult deleteResult = getMockMvc().perform(deleteClient).andExpect(status().isOk()).andReturn();
        BaseClientDetails deletedClientDetails = JsonUtils.readValue(deleteResult.getResponse().getContentAsString(), BaseClientDetails.class);
        assertEquals(client.getClientId(), deletedClientDetails.getClientId());
    }

    @Test
    public void createClient_withClientAdminToken_withAuthoritiesExcluded() throws Exception {
        String clientId = generator.generate().toLowerCase();
        LinkedHashSet excludedClaims = getWebApplicationContext().getBean("excludedClaims", LinkedHashSet.class);
        excludedClaims.add("authorities");
        try {
            String clientAdminToken = testClient.getClientCredentialsOAuthAccessToken(
                    testAccounts.getAdminClientId(),
                    testAccounts.getAdminClientSecret(),
                    "clients.admin");
            List<String> authorities = Arrays.asList("password.write", "scim.write", "scim.read");
            List<String> scopes = Arrays.asList("foo","bar","oauth.approvals");
            ClientDetailsModification client = createBaseClient(clientId, Collections.singleton("client_credentials"), authorities, scopes);
            MockHttpServletRequestBuilder createClientPost = post("/oauth/clients")
                    .header("Authorization", "Bearer " + clientAdminToken)
                    .accept(APPLICATION_JSON)
                    .contentType(APPLICATION_JSON)
                    .content(toString(client));
            ResultActions createResult = getMockMvc().perform(createClientPost).andExpect(status().isCreated());
            BaseClientDetails clientDetails = JsonUtils.readValue(createResult.andReturn().getResponse().getContentAsString(), BaseClientDetails.class);
            MockHttpServletRequestBuilder getClientMetadata = get("/oauth/clients/" + clientDetails.getClientId() + "/meta")
                .header("Authorization", "Bearer " + clientAdminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON);
            ResultActions getResult = getMockMvc().perform(getClientMetadata).andExpect(status().isOk());
            JsonUtils.readValue(getResult.andReturn().getResponse().getContentAsString(), ClientMetadata.class);
        } finally {
            excludedClaims.remove("authorities");
        }
    }

    @Test
    public void create_client_and_check_created_by() throws Exception {
        setupAdminUserToken();

        BaseClientDetails clientDetails = createClient(Arrays.asList("password.write", "scim.write", "scim.read", "clients.write"), adminUserToken);

        ClientMetadata clientMetadata = obtainClientMetadata(clientDetails.getClientId());
        SearchResults<Map<String, Object>> marissa = (SearchResults<Map<String, Object>>)scimUserEndpoints.findUsers("id,userName", "userName eq \"" + testUser.getUserName() + "\"", "userName", "asc", 0, 1);
        String marissaId = (String)marissa.getResources().iterator().next().get("id");
        assertEquals(marissaId, clientMetadata.getCreatedBy());

        String clientAdminToken = testClient.getClientCredentialsOAuthAccessToken(
            clientDetails.getClientId(),
            "secret",
            "clients.write");

        clientDetails = createClient(Arrays.asList("uaa.resource"), clientAdminToken);

        clientMetadata =obtainClientMetadata(clientDetails.getClientId());
        assertEquals(marissaId, clientMetadata.getCreatedBy());
    }

    private BaseClientDetails createClient(List<String> authorities, String token) throws Exception {
        String clientId = generator.generate().toLowerCase();
        List<String> scopes = Arrays.asList("foo","bar","oauth.approvals");
        ClientDetailsModification client = createBaseClient(clientId, Collections.singleton("client_credentials"), authorities, scopes);
        MockHttpServletRequestBuilder createClientPost = post("/oauth/clients")
            .header("Authorization", "Bearer " + adminUserToken)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content(toString(client));
        ResultActions createResult = getMockMvc().perform(createClientPost).andExpect(status().isCreated());
        return JsonUtils.readValue(createResult.andReturn().getResponse().getContentAsString(), BaseClientDetails.class);
    }

    private ClientMetadata obtainClientMetadata(String clientId) throws Exception {
        MockHttpServletRequestBuilder getClientMetadata = get("/oauth/clients/" + clientId + "/meta")
            .header("Authorization", "Bearer " + adminUserToken)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON);
        ResultActions getResult = getMockMvc().perform(getClientMetadata).andExpect(status().isOk());
        return JsonUtils.readValue(getResult.andReturn().getResponse().getContentAsString(), ClientMetadata.class);
    }

    @Test
    public void test_Read_Restricted_Scopes() throws Exception {
        MockHttpServletRequestBuilder createClientPost = get("/oauth/clients/restricted")
            .header("Authorization", "Bearer " + adminToken)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON);
        getMockMvc().perform(createClientPost)
            .andExpect(status().isOk())
            .andExpect(content().string(JsonUtils.writeValueAsString(new UaaScopes().getUaaScopes())));

    }

    @Test
    public void testCreate_RestrictedClient_Fails() throws Exception {
        String id = new RandomValueStringGenerator().generate();
        List<String> grantTypes = Arrays.asList("client_credentials", "password");
        BaseClientDetails clientWithAuthorities = createBaseClient(id, grantTypes, new UaaScopes().getUaaScopes(), null);
        BaseClientDetails clientWithScopes = createBaseClient(id, grantTypes, null, new UaaScopes().getUaaScopes());

        MockHttpServletRequestBuilder createClientPost = post("/oauth/clients/restricted")
            .header("Authorization", "Bearer " + adminToken)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content(toString(clientWithAuthorities));
        getMockMvc().perform(createClientPost).andExpect(status().isBadRequest());

        createClientPost = post("/oauth/clients/restricted")
            .header("Authorization", "Bearer " + adminToken)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content(toString(clientWithScopes));
        getMockMvc().perform(createClientPost).andExpect(status().isBadRequest());
    }

    @Test
    public void testCreate_RestrictedClient_Succeeds() throws Exception {
        String id = new RandomValueStringGenerator().generate();
        List<String> scopes = Collections.singletonList("openid");
        BaseClientDetails client = createBaseClient(id, Arrays.asList("client_credentials", "password"), scopes, scopes);

        MockHttpServletRequestBuilder createClientPost = post("/oauth/clients/restricted")
            .header("Authorization", "Bearer " + adminToken)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content(toString(client));
        getMockMvc().perform(createClientPost).andExpect(status().isCreated());

        createClientPost = put("/oauth/clients/restricted/"+id)
            .header("Authorization", "Bearer " + adminToken)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content(toString(client));
        getMockMvc().perform(createClientPost).andExpect(status().isOk());

        client.setScope(new UaaScopes().getUaaScopes());
        createClientPost = put("/oauth/clients/restricted/" + id)
            .header("Authorization", "Bearer " + adminToken)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content(toString(client));
        getMockMvc().perform(createClientPost).andExpect(status().isBadRequest());
    }

    @Test
    public void testCreateClientsTxSuccess() throws Exception {
        int count = 5;
        BaseClientDetails[] details = createBaseClients(count, null);
        MockHttpServletRequestBuilder createClientPost = post("/oauth/clients/tx")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(toString(details));
        ResultActions result = getMockMvc().perform(createClientPost);
        result.andExpect(status().isCreated());
        ClientDetails[] clients = clientArrayFromString(result.andReturn().getResponse().getContentAsString());
        for (ClientDetails client : clients) {
            ClientDetails c = getClient(client.getClientId());
            assertNotNull(c);
            assertNull(c.getClientSecret());
        }
        verify(applicationEventPublisher, times(count)).publishEvent(captor.capture());
        for (AbstractUaaEvent event : captor.getAllValues()) {
            assertEquals(AuditEventType.ClientCreateSuccess, event.getAuditEvent().getType());
        }
    }

    @Test
    public void testCreateClientsTxDuplicateId() throws Exception {
        BaseClientDetails[] details = createBaseClients(5, null);
        details[details.length-1] = details[0];
        MockHttpServletRequestBuilder createClientPost = post("/oauth/clients/tx")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(toString(details));
        getMockMvc().perform(createClientPost).andExpect(status().isConflict());
        for (ClientDetails client : details) {
            assertNull(getClient(client.getClientId()));
        }
        verify(applicationEventPublisher, times(0)).publishEvent(captor.capture());
    }

    @Test
    public void test_InZone_ClientWrite_Using_ZonesDotAdmin() throws Exception {
        String subdomain = generator.generate();
        MockMvcUtils.IdentityZoneCreationResult result = MockMvcUtils.utils().createOtherIdentityZoneAndReturnResult(subdomain, getMockMvc(), getWebApplicationContext(), null);
        String clientId = generator.generate();
        BaseClientDetails client = new BaseClientDetails(clientId, "", "openid","authorization_code","","http://some.redirect.url.com");
        client.setClientSecret("secret");
        MockMvcUtils.utils().createClient(getMockMvc(), result.getZoneAdminToken(), client, result.getIdentityZone());
    }

    @Test
    public void test_InZone_ClientWrite_Using_ZonesDotClientsDotAdmin() throws Exception {
        String subdomain = generator.generate();
        MockMvcUtils.IdentityZoneCreationResult result = MockMvcUtils.utils().createOtherIdentityZoneAndReturnResult(subdomain, getMockMvc(), getWebApplicationContext(), null);
        String id = result.getIdentityZone().getId();
        String clientId = generator.generate();
        BaseClientDetails client = new BaseClientDetails(clientId, "", "","client_credentials","zones."+id+".clients.admin", "http://some.redirect.url.com");
        client.setClientSecret("secret");
        client = MockMvcUtils.utils().createClient(getMockMvc(), adminToken, client);
        client.setClientSecret("secret");

        String zonesClientsAdminToken = MockMvcUtils.utils().getClientOAuthAccessToken(getMockMvc(), client.getClientId(), client.getClientSecret(), "zones." + id + ".clients.admin");

        BaseClientDetails newclient = new BaseClientDetails(clientId, "", "openid","authorization_code","","http://some.redirect.url.com");
        newclient.setClientSecret("secret");
        newclient = MockMvcUtils.utils().createClient(getMockMvc(), zonesClientsAdminToken, newclient, result.getIdentityZone());

        MockMvcUtils.utils().updateClient(getMockMvc(), zonesClientsAdminToken, newclient, result.getIdentityZone());
    }

    @Test
    public void manageClientInOtherZone_Using_AdminUserTokenFromDefaultZone() throws Exception {
        String subdomain = generator.generate();
        MockMvcUtils.IdentityZoneCreationResult result = MockMvcUtils.utils().createOtherIdentityZoneAndReturnResult(subdomain, getMockMvc(), getWebApplicationContext(), null);
        String zoneId = result.getIdentityZone().getId();
        String clientId = generator.generate();

        setupAdminUserToken();

        BaseClientDetails client = new BaseClientDetails(clientId, "", "openid","authorization_code","","http://some.redirect.url.com");
        client.setClientSecret("secret");
        BaseClientDetails createdClient = MockMvcUtils.utils().createClient(getMockMvc(), adminUserToken, client, result.getIdentityZone());

        assertEquals(client.getClientId(), createdClient.getClientId());

        MockHttpServletRequestBuilder getClient = get("/oauth/clients/" + client.getClientId())
                .header("Authorization", "Bearer " + adminUserToken)
                .header("X-Identity-Zone-Id", zoneId)
                .accept(APPLICATION_JSON);
        MvcResult mvcResult = getMockMvc().perform(getClient)
                .andExpect(status().isOk())
                .andReturn();
        BaseClientDetails clientDetails = JsonUtils.readValue(mvcResult.getResponse().getContentAsString(), BaseClientDetails.class);
        assertEquals(client.getClientId(), clientDetails.getClientId());

        clientDetails.setAuthorizedGrantTypes(Collections.singleton("authorization_code"));
        MockHttpServletRequestBuilder updateClient = put("/oauth/clients/" + client.getClientId())
                .header("Authorization", "Bearer" + adminUserToken)
                .header("X-Identity-Zone-Id", zoneId)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(clientDetails));
        mvcResult = getMockMvc().perform(updateClient).andExpect(status().isOk()).andReturn();
        BaseClientDetails updatedClientDetails = JsonUtils.readValue(mvcResult.getResponse().getContentAsString(), BaseClientDetails.class);
        assertEquals(client.getClientId(), updatedClientDetails.getClientId());
        assertThat(updatedClientDetails.getAuthorizedGrantTypes(), PredicateMatcher.<String>has(m -> m.equals("authorization_code")));

        MockHttpServletRequestBuilder deleteClient = delete("/oauth/clients/" + client.getClientId())
                .header("Authorization", "Bearer" + adminUserToken)
                .header("X-Identity-Zone-Id", zoneId)
                .accept(APPLICATION_JSON);
        MvcResult deleteResult = getMockMvc().perform(deleteClient).andExpect(status().isOk()).andReturn();
        BaseClientDetails deletedClientDetails = JsonUtils.readValue(deleteResult.getResponse().getContentAsString(), BaseClientDetails.class);
        assertEquals(client.getClientId(), deletedClientDetails.getClientId());

    }

    @Test
    public void test_InZone_ClientRead_Using_ZonesDotClientsDotAdmin() throws Exception {
        String subdomain = generator.generate();
        MockMvcUtils.IdentityZoneCreationResult result = MockMvcUtils.utils().createOtherIdentityZoneAndReturnResult(subdomain, getMockMvc(), getWebApplicationContext(), null);
        String id = result.getIdentityZone().getId();
        String clientId = generator.generate();
        BaseClientDetails client = new BaseClientDetails(clientId, "", "","client_credentials","zones."+id+".clients.admin","http://some.redirect.url.com");
        client.setClientSecret("secret");
        client = MockMvcUtils.utils().createClient(getMockMvc(), adminToken, client);
        client.setClientSecret("secret");

        String zonesClientsAdminToken = MockMvcUtils.utils().getClientOAuthAccessToken(getMockMvc(), client.getClientId(), client.getClientSecret(), "zones."+id+".clients.admin");

        BaseClientDetails newclient = new BaseClientDetails(clientId, "", "openid","authorization_code","","http://some.redirect.url.com");
        newclient.setClientSecret("secret");
        MockMvcUtils.utils().createClient(getMockMvc(), zonesClientsAdminToken, newclient, result.getIdentityZone());
    }

    @Test
    public void test_InZone_ClientRead_Using_ZonesDotClientsDotRead() throws Exception {
        String subdomain = generator.generate();
        MockMvcUtils.IdentityZoneCreationResult result = MockMvcUtils.utils().createOtherIdentityZoneAndReturnResult(subdomain, getMockMvc(), getWebApplicationContext(), null);
        String id = result.getIdentityZone().getId();
        String clientId = generator.generate();
        BaseClientDetails client = new BaseClientDetails(clientId, "", "","client_credentials","zones."+id+".clients.read","http://some.redirect.url.com");
        client.setClientSecret("secret");
        client = MockMvcUtils.utils().createClient(getMockMvc(), adminToken, client);
        client.setClientSecret("secret");

        String zonesClientsReadToken = MockMvcUtils.utils().getClientOAuthAccessToken(getMockMvc(), client.getClientId(), client.getClientSecret(), "zones." + id + ".clients.read");

        BaseClientDetails newclient = new BaseClientDetails(clientId, "", "openid","authorization_code","","http://some.redirect.url.com");
        newclient.setClientSecret("secret");
        MockMvcUtils.utils().createClient(getMockMvc(), result.getZoneAdminToken(), newclient, result.getIdentityZone());

        MockMvcUtils.utils().getClient(getMockMvc(), zonesClientsReadToken, newclient.getClientId(), result.getIdentityZone());
    }

    @Test
    public void testCreateClientsTxClientCredentialsWithoutSecret() throws Exception {
        BaseClientDetails[] details = createBaseClients(5, null);
        details[details.length-1].setAuthorizedGrantTypes(StringUtils.commaDelimitedListToSet("client_credentials"));
        details[details.length-1].setClientSecret(null);
        MockHttpServletRequestBuilder createClientPost = post("/oauth/clients/tx")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(toString(details));
        getMockMvc().perform(createClientPost).andExpect(status().isBadRequest());
        for (ClientDetails client : details) {
            assertNull(getClient(client.getClientId()));
        }
        verify(applicationEventPublisher, times(0)).publishEvent(captor.capture());
    }

    @Test
    public void testUpdateClientsTxSuccess() throws Exception {
        int count = 5;
        BaseClientDetails[] details = new BaseClientDetails[count];
        for (int i=0; i<details.length; i++) {
            details[i] = (BaseClientDetails)createClient(adminToken,null,null);
            details[i].setRefreshTokenValiditySeconds(120);
        }
        MockHttpServletRequestBuilder updateClientPut = put("/oauth/clients/tx")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(toString(details));
        ResultActions result = getMockMvc().perform(updateClientPut);
        result.andExpect(status().isOk());
        ClientDetails[] clients = clientArrayFromString(result.andReturn().getResponse().getContentAsString());
        for (ClientDetails client : clients) {
            assertNotNull(getClient(client.getClientId()));
            assertEquals(new Integer(120), client.getRefreshTokenValiditySeconds());
        }
        //create and then update events
        verify(applicationEventPublisher, times(count * 2)).publishEvent(captor.capture());
        int index = 0;
        for (AbstractUaaEvent event : captor.getAllValues()) {
            if (index<count) {
                assertEquals(AuditEventType.ClientCreateSuccess, event.getAuditEvent().getType());
            } else {
                assertEquals(AuditEventType.ClientUpdateSuccess, event.getAuditEvent().getType());
            }
            index++;
        }
    }

    @Test
    public void testUpdateClientsTxInvalidId() throws Exception {
        int count = 5;
        BaseClientDetails[] details = new BaseClientDetails[count];
        for (int i=0; i<details.length; i++) {
            details[i] = (BaseClientDetails)createClient(adminToken,null,null);
            details[i].setRefreshTokenValiditySeconds(120);
        }
        String firstId = details[0].getClientId();
        details[0].setClientId("unknown.client.id");

        MockHttpServletRequestBuilder updateClientPut = put("/oauth/clients/tx")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(toString(details));
        ResultActions result = getMockMvc().perform(updateClientPut);
        result.andExpect(status().isNotFound());
        details[0].setClientId(firstId);
        for (ClientDetails client : details) {
            ClientDetails c = getClient(client.getClientId());
            assertNotNull(c);
            assertNull(c.getClientSecret());
            assertNull(c.getRefreshTokenValiditySeconds());
        }
        //create and then update events
        verify(applicationEventPublisher, times(count)).publishEvent(captor.capture());
    }

    @Test
    public void testDeleteClientsTxSuccess() throws Exception {
        int count = 5;
        BaseClientDetails[] details = new BaseClientDetails[count];
        for (int i=0; i<details.length; i++) {
            details[i] = (BaseClientDetails)createClient(adminToken,null,null);
        }
        MockHttpServletRequestBuilder deleteClientsPost = post("/oauth/clients/tx/delete")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(toString(details));
        ResultActions result = getMockMvc().perform(deleteClientsPost);
        result.andExpect(status().isOk());
        for (ClientDetails client : details) {
            assertNull(getClient(client.getClientId()));
        }
        //create and then update events
        verify(applicationEventPublisher, times(count*2)).publishEvent(captor.capture());
        int index = 0;
        for (AbstractUaaEvent event : captor.getAllValues()) {
            if (index<count) {
                assertEquals(AuditEventType.ClientCreateSuccess, event.getAuditEvent().getType());
            } else {
                assertEquals(AuditEventType.ClientDeleteSuccess, event.getAuditEvent().getType());
            }
            index++;
        }
    }

    @Test
    public void testDeleteClientsTxRollbackInvalidId() throws Exception {
        int count = 5;
        BaseClientDetails[] details = new BaseClientDetails[count];
        for (int i=0; i<details.length; i++) {
            details[i] = (BaseClientDetails)createClient(adminToken,null,null);
        }
        String firstId = details[0].getClientId();
        details[0].setClientId("unknown.client.id");

        MockHttpServletRequestBuilder deleteClientsPost = post("/oauth/clients/tx/delete")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(toString(details));
        ResultActions result = getMockMvc().perform(deleteClientsPost);
        result.andExpect(status().isNotFound());
        details[0].setClientId(firstId);
        for (ClientDetails client : details) {
            ClientDetails c = getClient(client.getClientId());
            assertNotNull(c);
            assertNull(c.getClientSecret());
            assertNull(c.getRefreshTokenValiditySeconds());
        }
        verify(applicationEventPublisher, times(count)).publishEvent(captor.capture());
    }

    @Test
    public void testAddUpdateDeleteClientsTxSuccess() throws Exception {
        int count = 5;
        ClientDetailsModification[] details = new ClientDetailsModification[count*3];
        for (int i=0; i<count; i++) {
            details[i] = (ClientDetailsModification)createClient(adminToken,null,null);
            details[i].setRefreshTokenValiditySeconds(120);
            details[i].setAction(ClientDetailsModification.UPDATE);
        }
        for (int i=count; i<(count*2); i++) {
            details[i] = (ClientDetailsModification)createClient(adminToken,null,null);
            details[i].setAction(ClientDetailsModification.DELETE);
        }
        for (int i=(count*2); i<(count*3); i++) {
            details[i] = createBaseClient(null,null);
            details[i].setAction(ClientDetailsModification.ADD);
        }


        MockHttpServletRequestBuilder modifyClientsPost = post("/oauth/clients/tx/modify")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(toString(details));
        ResultActions result = getMockMvc().perform(modifyClientsPost);
        result.andExpect(status().isOk());

        for (int i=0; i<count; i++) {
            ClientDetails c = getClient(details[i].getClientId());
            assertNotNull(c);
            assertEquals(new Integer(120), c.getRefreshTokenValiditySeconds());

        }
        for (int i=count; i<(count*2); i++) {
            ClientDetails c = getClient(details[i].getClientId());
            assertNull(c);
        }
        for (int i=(count*2); i<(count*3); i++) {
            ClientDetails c = getClient(details[i].getClientId());
            assertNotNull(c);
            assertNull(c.getRefreshTokenValiditySeconds());
        }
        verify(applicationEventPublisher, times(count*5)).publishEvent(captor.capture());
        int index = 0;
        for (AbstractUaaEvent event : captor.getAllValues()) {
            int swit = index / count;
            switch (swit) {
                case 0 :
                case 1 :
                case 4 : {
                    //1-10 and 21-25 events are create
                    assertEquals(AuditEventType.ClientCreateSuccess, event.getAuditEvent().getType());
                    assertEquals(ClientCreateEvent.class, event.getClass());
                    assertEquals(details[index<10?index:(index-count*2)].getClientId(), event.getAuditEvent().getPrincipalId());
                    break;
                }
                case 2 : {
                    //the 11-15 events are update
                    assertEquals(AuditEventType.ClientUpdateSuccess, event.getAuditEvent().getType());
                    assertEquals(ClientUpdateEvent.class, event.getClass());
                    assertEquals(details[index-(count*2)].getClientId(), event.getAuditEvent().getPrincipalId());
                    break;
                }
                case 3 : {
                    //the 16-20 events are deletes
                    assertEquals(AuditEventType.ClientDeleteSuccess, event.getAuditEvent().getType());
                    assertEquals(ClientDeleteEvent.class, event.getClass());
                    assertEquals(details[index-count*2].getClientId(), event.getAuditEvent().getPrincipalId());
                    break;
                }
            }
            index++;
        }
    }

    @Test
    public void testAddUpdateDeleteClientsTxDeleteFailedRollback() throws Exception {
        ClientDetailsModification[] details = new ClientDetailsModification[15];
        for (int i=0; i<5; i++) {
            details[i] = (ClientDetailsModification)createClient(adminToken,null,Collections.singleton("password"));
            details[i].setRefreshTokenValiditySeconds(120);
            details[i].setAction(ClientDetailsModification.UPDATE);
        }
        for (int i=5; i<10; i++) {
            details[i] = (ClientDetailsModification)createClient(adminToken,null,null);
            details[i].setAction(ClientDetailsModification.DELETE);
        }
        for (int i=10; i<15; i++) {
            details[i] = createBaseClient(null,null);
            details[i].setAction(ClientDetailsModification.ADD);
        }

        String userToken = testClient.getUserOAuthAccessToken(
                details[0].getClientId(),
                "secret",
                testUser.getUserName(),
                testPassword,
                "oauth.approvals");
        addApprovals(userToken, details[0].getClientId());
        Approval[] approvals = getApprovals(userToken, details[0].getClientId());
        assertEquals(3, approvals.length);


        String deleteId = details[5].getClientId();
        details[5].setClientId("unknown.client.id");

        MockHttpServletRequestBuilder modifyClientsPost = post("/oauth/clients/tx/modify")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(toString(details));
        ResultActions result = getMockMvc().perform(modifyClientsPost);
        result.andExpect(status().isNotFound());
        details[5].setClientId(deleteId);

        for (int i=0; i<5; i++) {
            ClientDetails c = getClient(details[i].getClientId());
            assertNotNull(c);
            assertNull(c.getRefreshTokenValiditySeconds());

        }
        for (int i=5; i<10; i++) {
            ClientDetails c = getClient(details[i].getClientId());
            assertNotNull(c);
        }
        for (int i=10; i<15; i++) {
            ClientDetails c = getClient(details[i].getClientId());
            assertNull(c);
        }
        approvals = getApprovals(userToken, details[0].getClientId());
        assertEquals(3, approvals.length);
    }

    @Test
    public void testApprovalsAreDeleted() throws Exception {
        ClientDetails details = createClient(adminToken, new RandomValueStringGenerator().generate(), Collections.singleton("password"));
        String userToken = testClient.getUserOAuthAccessToken(
                details.getClientId(),
                "secret",
                testUser.getUserName(),
                testPassword,
                "oauth.approvals");
        Approval[] approvals = getApprovals(userToken, details.getClientId());
        assertEquals(0, approvals.length);
        addApprovals(userToken, details.getClientId());
        approvals = getApprovals(userToken, details.getClientId());
        assertEquals(3, approvals.length);

        MockHttpServletRequestBuilder deleteClientsPost = post("/oauth/clients/tx/delete")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(toString(new ClientDetails[]{details}));
        ResultActions result = getMockMvc().perform(deleteClientsPost);
        result.andExpect(status().isOk());


        ClientDetailsModification[] deleted = (ClientDetailsModification[]) arrayFromString(result.andReturn().getResponse().getContentAsString(), ClientDetailsModification[].class);
        assertTrue(deleted[0].isApprovalsDeleted());
        verify(applicationEventPublisher, times(2)).publishEvent(captor.capture());

        ClientDetails approvalsClient = createApprovalsLoginClient(adminToken);
        String loginToken = testClient.getUserOAuthAccessToken(
                approvalsClient.getClientId(),
                "secret",
                testUser.getUserName(),
                testPassword,
                "oauth.approvals");

        approvals = getApprovals(loginToken, details.getClientId());
        assertEquals(0, approvals.length);

    }

    @Test
    public void testApprovalsAreDeleted2() throws Exception {
        ClientDetails details = createClient(adminToken, new RandomValueStringGenerator().generate(), Collections.singleton("password"));
        String userToken = testClient.getUserOAuthAccessToken(
                            details.getClientId(),
                            "secret",
                            testUser.getUserName(),
                            testPassword,
                            "oauth.approvals");
        Approval[] approvals = getApprovals(userToken, details.getClientId());
        assertEquals(0, approvals.length);
        addApprovals(userToken, details.getClientId());
        approvals = getApprovals(userToken, details.getClientId());
        assertEquals(3, approvals.length);

        MockHttpServletRequestBuilder deleteClientsPost = delete("/oauth/clients/"+details.getClientId())
                        .header("Authorization", "Bearer " + adminToken)
                        .accept(APPLICATION_JSON);
        ResultActions result = getMockMvc().perform(deleteClientsPost);
        result.andExpect(status().isOk());

        ClientDetails approvalsClient = createApprovalsLoginClient(adminToken);
        String loginToken = testClient.getUserOAuthAccessToken(
                approvalsClient.getClientId(),
                "secret",
                testUser.getUserName(),
                testPassword,
                "oauth.approvals");

        approvals = getApprovals(loginToken, details.getClientId());
        assertEquals(0, approvals.length);
    }

    @Test
    public void testModifyApprovalsAreDeleted() throws Exception {
        ClientDetails details = createClient(adminToken, new RandomValueStringGenerator().generate(), Collections.singleton("password"));
        ((ClientDetailsModification)details).setAction(ClientDetailsModification.DELETE);
        String userToken = testClient.getUserOAuthAccessToken(
            details.getClientId(),
            "secret",
            testUser.getUserName(),
            testPassword,
            "oauth.approvals");
        Approval[] approvals = getApprovals(userToken, details.getClientId());
        assertEquals(0, approvals.length);
        addApprovals(userToken, details.getClientId());
        approvals = getApprovals(userToken, details.getClientId());
        assertEquals(3, approvals.length);

        MockHttpServletRequestBuilder deleteClientsPost = post("/oauth/clients/tx/modify")
            .header("Authorization", "Bearer " + adminToken)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content(toString(new ClientDetails[]{details}));
        ResultActions result = getMockMvc().perform(deleteClientsPost);
        result.andExpect(status().isOk());
        ClientDetailsModification[] deleted = (ClientDetailsModification[]) arrayFromString(result.andReturn().getResponse().getContentAsString(), ClientDetailsModification[].class);
        assertTrue(deleted[0].isApprovalsDeleted());
        verify(applicationEventPublisher, times(2)).publishEvent(captor.capture());

        ClientDetails approvalsClient = createApprovalsLoginClient(adminToken);
        String loginToken = testClient.getUserOAuthAccessToken(
            approvalsClient.getClientId(),
            "secret",
            testUser.getUserName(),
            testPassword,
            "oauth.approvals");
        approvals = getApprovals(loginToken, details.getClientId());
        assertEquals(0, approvals.length);
    }

    @Test
    public void testSecretChangeTxApprovalsNotDeleted() throws Exception {
        int count = 3;
        //create clients
        ClientDetailsModification[] clients = createBaseClients(count, Arrays.asList("client_credentials", "password"));
        for (ClientDetailsModification c : clients) {
            c.setAction(c.ADD);
        }
        MockHttpServletRequestBuilder modifyClientsPost = post("/oauth/clients/tx/modify")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(toString(clients));
        ResultActions result = getMockMvc().perform(modifyClientsPost);
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
            assertEquals(3, getApprovals(userToken,c.getClientId()).length);
        }

        //change the secret, and we know the old secret
        SecretChangeRequest[] srs = new SecretChangeRequest[clients.length];
        for (int i=0; i<srs.length; i++) {
            srs[i] = new SecretChangeRequest();
            srs[i].setClientId(clients[i].getClientId());
            srs[i].setOldSecret(clients[i].getClientSecret());
            srs[i].setSecret("secret2");
        }
        modifyClientsPost = post("/oauth/clients/tx/secret")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(toString(srs));
        result = getMockMvc().perform(modifyClientsPost);
        result.andExpect(status().isOk());

        clients = (ClientDetailsModification[])arrayFromString(result.andReturn().getResponse().getContentAsString(), ClientDetailsModification[].class);

        //check that we still have approvals for each client
        ClientDetails approvalsClient = createApprovalsLoginClient(adminToken);

        for (ClientDetailsModification c : clients) {
            String loginToken = testClient.getUserOAuthAccessToken(
                    approvalsClient.getClientId(),
                    "secret",
                    testUser.getUserName(),
                    testPassword,
                    "oauth.approvals");
            assertEquals(3, getApprovals(loginToken,c.getClientId()).length);
            assertFalse(c.isApprovalsDeleted());
        }

    }

    @Test
    public void testSecretChangeEvent() throws Exception {
        String token = testClient.getClientCredentialsOAuthAccessToken(
                testAccounts.getAdminClientId(),
                testAccounts.getAdminClientSecret(),
                "uaa.admin,clients.secret");
        String id = "secretchangeevent";
        ClientDetails c = createClient(token, id, Collections.singleton("client_credentials"));
        SecretChangeRequest request = new SecretChangeRequest(id, "secret", "newsecret");
        MockHttpServletRequestBuilder modifyClientsPost = put("/oauth/clients/" + id + "/secret")
            .header("Authorization", "Bearer " + token)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content(toString(request));
        getMockMvc().perform(modifyClientsPost)
            .andExpect(status().isOk());
        verify(applicationEventPublisher, times(2)).publishEvent(captor.capture());
        assertEquals(SecretChangeEvent.class, captor.getValue().getClass());
        SecretChangeEvent event = (SecretChangeEvent) captor.getValue();
        assertEquals(id, event.getAuditEvent().getPrincipalId());
    }

    @Test
    public void testAddNewClientSecret() throws Exception {
        String token = testClient.getClientCredentialsOAuthAccessToken(
            testAccounts.getAdminClientId(),
            testAccounts.getAdminClientSecret(),
            "uaa.admin,clients.secret");
        String id = generator.generate();
        ClientDetails client = createClient(token, id, Collections.singleton("client_credentials"));
        SecretChangeRequest request = new SecretChangeRequest();
        request.setSecret("password2");
        request.setChangeMode(ADD);
        MockHttpServletResponse response = getMockMvc().perform(put("/oauth/clients/{client_id}/secret", client.getClientId())
            .header("Authorization", "Bearer " + token)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content(toString(request)))
            .andExpect(status().isOk())
            .andReturn().getResponse();

        ActionResult actionResult = JsonUtils.readValue(response.getContentAsString(), ActionResult.class);
        assertEquals("ok", actionResult.getStatus());
        assertEquals("Secret is added", actionResult.getMessage());

        verify(applicationEventPublisher, times(2)).publishEvent(captor.capture());
        assertEquals(SecretChangeEvent.class, captor.getValue().getClass());
        SecretChangeEvent event = (SecretChangeEvent) captor.getValue();
        assertEquals(id, event.getAuditEvent().getPrincipalId());
    }

    @Test
    public void testAddMoreThanTwoClientSecret() throws Exception {
        String token = testClient.getClientCredentialsOAuthAccessToken(
            testAccounts.getAdminClientId(),
            testAccounts.getAdminClientSecret(),
            "uaa.admin,clients.secret");
        String id = generator.generate();
        ClientDetails client = createClient(token, id, Collections.singleton("client_credentials"));
        SecretChangeRequest request = new SecretChangeRequest();
        request.setSecret("password2");
        request.setChangeMode(ADD);
        getMockMvc().perform(put("/oauth/clients/{client_id}/secret", client.getClientId())
            .header("Authorization", "Bearer " + token)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content(toString(request)))
            .andExpect(status().isOk());

        request.setSecret("password3");
        MockHttpServletResponse response = getMockMvc().perform(put("/oauth/clients/{client_id}/secret", client.getClientId())
            .header("Authorization", "Bearer " + token)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content(toString(request)))
            .andExpect(status().isBadRequest())
            .andReturn().getResponse();

        UaaException invalidClientDetailsException = JsonUtils.readValue(response.getContentAsString(), UaaException.class);
        assertEquals("invalid_client", invalidClientDetailsException.getErrorCode());
        assertEquals("client secret is either empty or client already has two secrets.", invalidClientDetailsException.getMessage());
        verify(applicationEventPublisher, times(3)).publishEvent(captor.capture());
        assertEquals(SecretFailureEvent.class, captor.getValue().getClass());
        SecretFailureEvent event = (SecretFailureEvent) captor.getValue();
        assertEquals(id, event.getAuditEvent().getPrincipalId());
    }

    @Test
    public void testDeleteClientSecret() throws Exception {
        String token = testClient.getClientCredentialsOAuthAccessToken(
            testAccounts.getAdminClientId(),
            testAccounts.getAdminClientSecret(),
            "uaa.admin,clients.secret");
        String id = generator.generate();
        ClientDetails client = createClient(token, id, Collections.singleton("client_credentials"));
        SecretChangeRequest request = new SecretChangeRequest();
        request.setSecret("password2");
        request.setChangeMode(ADD);
        getMockMvc().perform(put("/oauth/clients/{client_id}/secret", client.getClientId())
            .header("Authorization", "Bearer " + token)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content(toString(request)))
            .andExpect(status().isOk());

        request = new SecretChangeRequest();
        request.setChangeMode(DELETE);
        MockHttpServletResponse response = getMockMvc().perform(put("/oauth/clients/{client_id}/secret", client.getClientId())
            .header("Authorization", "Bearer " + token)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content(toString(request)))
            .andExpect(status().isOk())
            .andReturn().getResponse();

        ActionResult actionResult = JsonUtils.readValue(response.getContentAsString(), ActionResult.class);
        assertNotNull(actionResult);
        assertEquals("ok", actionResult.getStatus());
        assertEquals("Secret is deleted", actionResult.getMessage());

        verify(applicationEventPublisher, times(3)).publishEvent(captor.capture());
        assertEquals(SecretChangeEvent.class, captor.getValue().getClass());
        SecretChangeEvent event = (SecretChangeEvent) captor.getValue();
        assertEquals(id, event.getAuditEvent().getPrincipalId());
    }

    @Test
    public void testDeleteClientSecretForClientWithOneSecret() throws Exception {
        String token = testClient.getClientCredentialsOAuthAccessToken(
            testAccounts.getAdminClientId(),
            testAccounts.getAdminClientSecret(),
            "uaa.admin,clients.secret");
        String id = generator.generate();
        ClientDetails client = createClient(token, id, Collections.singleton("client_credentials"));

        SecretChangeRequest request = new SecretChangeRequest();
        request.setChangeMode(DELETE);
        MockHttpServletResponse response = getMockMvc().perform(put("/oauth/clients/{client_id}/secret", client.getClientId())
            .header("Authorization", "Bearer " + token)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content(toString(request)))
            .andExpect(status().isBadRequest())
            .andReturn().getResponse();

        UaaException invalidClientDetailsException = JsonUtils.readValue(response.getContentAsString(), UaaException.class);
        assertEquals("invalid_client", invalidClientDetailsException.getErrorCode());
        assertEquals("client secret is either empty or client has only one secret.", invalidClientDetailsException.getMessage());

        verify(applicationEventPublisher, times(2)).publishEvent(captor.capture());
        assertEquals(SecretFailureEvent.class, captor.getValue().getClass());
        SecretFailureEvent event = (SecretFailureEvent) captor.getValue();
        assertEquals(id, event.getAuditEvent().getPrincipalId());
    }

    @Test
    public void testSecretChange_UsingAdminClientToken() throws Exception {
        String adminToken = testClient.getClientCredentialsOAuthAccessToken(
                testAccounts.getAdminClientId(),
                testAccounts.getAdminClientSecret(),
                "uaa.admin");
        String id = generator.generate();
        BaseClientDetails c = (BaseClientDetails) createClient(adminToken, id, Collections.singleton("client_credentials"));
        SecretChangeRequest request = new SecretChangeRequest(id, null, "newsecret");

        MockHttpServletRequestBuilder modifySecret = put("/oauth/clients/" + id + "/secret")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(toString(request));

        getMockMvc().perform(modifySecret).andExpect(status().isOk());
    }

    @Test
    public void testSecretChange_UsingClientAdminToken() throws Exception {
        String adminToken = testClient.getClientCredentialsOAuthAccessToken(
          testAccounts.getAdminClientId(),
          testAccounts.getAdminClientSecret(),
          "clients.admin");
        String id = generator.generate();
        BaseClientDetails c = (BaseClientDetails) createClient(adminToken, id, Collections.singleton("client_credentials"));
        SecretChangeRequest request = new SecretChangeRequest(id, null, "newersecret");

        MockHttpServletRequestBuilder modifySecret = put("/oauth/clients/" + id + "/secret")
          .header("Authorization", "Bearer " + adminToken)
          .accept(APPLICATION_JSON)
          .contentType(APPLICATION_JSON)
          .content(toString(request));

        getMockMvc().perform(modifySecret).andExpect(status().isOk());
    }

    @Test
    public void testFailedSecretChangeEvent() throws Exception {

        List<String> scopes = Arrays.asList("oauth.approvals","clients.secret");
        BaseClientDetails client = createBaseClient(null, Arrays.asList("password", "client_credentials"), scopes, scopes);
        MockHttpServletRequestBuilder createClientPost = post("/oauth/clients")
            .header("Authorization", "Bearer " + adminToken)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content(toString(client));
        getMockMvc().perform(createClientPost).andExpect(status().isCreated());

        String clientSecretToken = testClient.getClientCredentialsOAuthAccessToken(client.getClientId(), client.getClientSecret(), "clients.secret");

        SecretChangeRequest request = new SecretChangeRequest(client.getClientId(), "invalidsecret", "newsecret");
        MockHttpServletRequestBuilder modifyClientsPost = put("/oauth/clients/" + client.getClientId() + "/secret")
            .header("Authorization", "Bearer " + clientSecretToken)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content(toString(request));
        getMockMvc().perform(modifyClientsPost)
            .andExpect(status().isBadRequest());
        verify(applicationEventPublisher, times(2)).publishEvent(captor.capture());
        assertEquals(SecretFailureEvent.class, captor.getValue().getClass());
        SecretFailureEvent event = (SecretFailureEvent) captor.getValue();
        assertEquals(client.getClientId(), event.getAuditEvent().getPrincipalId());
    }

    @Test
    public void testSecretChangeModifyTxApprovalsDeleted() throws Exception {
        int count = 3;
        //create clients
        ClientDetailsModification[] clients = createBaseClients(count, Arrays.asList("client_credentials","password"));
        for (ClientDetailsModification c : clients) {
            c.setAction(c.ADD);
        }
        MockHttpServletRequestBuilder modifyClientsPost = post("/oauth/clients/tx/modify")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(toString(clients));
        ResultActions result = getMockMvc().perform(modifyClientsPost);
        result.andExpect(status().isOk());

        clients = (ClientDetailsModification[])arrayFromString(result.andReturn().getResponse().getContentAsString(), ClientDetailsModification[].class);

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
            assertEquals(3, getApprovals(userToken,c.getClientId()).length);
        }

        //change the secret, and we know don't the old secret
        for (ClientDetailsModification c : clients) {
            c.setClientSecret("secret2");
            c.setAction(c.UPDATE_SECRET);
        }
        modifyClientsPost = post("/oauth/clients/tx/modify")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(toString(clients));
        result = getMockMvc().perform(modifyClientsPost);
        result.andExpect(status().isOk());
        clients = (ClientDetailsModification[])arrayFromString(result.andReturn().getResponse().getContentAsString(), ClientDetailsModification[].class);

        //check that we deleted approvals for each client
        for (ClientDetailsModification c : clients) {
            String userToken = testClient.getUserOAuthAccessToken(
                    c.getClientId(),
                    "secret2",
                    testUser.getUserName(),
                    testPassword,
                    "oauth.approvals");
            assertEquals(0, getApprovals(userToken,c.getClientId()).length);
            assertTrue(c.isApprovalsDeleted());
        }

        //verify(applicationEventPublisher, times(count*3)).publishEvent(captor.capture());
        verify(applicationEventPublisher, times(12)).publishEvent(captor.capture());
        int index = 0;
        for (AbstractUaaEvent event : captor.getAllValues()) {
            if (index<count) {
                assertEquals(AuditEventType.ClientCreateSuccess, event.getAuditEvent().getType());
            } else {
                int swit = index % 3;
                if (swit==0) {
                    assertEquals(AuditEventType.ClientUpdateSuccess, event.getAuditEvent().getType());
                } else if (swit==1) {
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
    public void testSecretChangeModifyTxApprovalsNotDeleted() throws Exception {
        //create clients
        ClientDetailsModification[] clients = createBaseClients(3, Arrays.asList("client_credentials","password"));
        for (ClientDetailsModification c : clients) {
            c.setAction(c.ADD);
        }
        MockHttpServletRequestBuilder modifyClientsPost = post("/oauth/clients/tx/modify")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(toString(clients));
        ResultActions result = getMockMvc().perform(modifyClientsPost);
        result.andExpect(status().isOk());

        clients = (ClientDetailsModification[])arrayFromString(result.andReturn().getResponse().getContentAsString(), ClientDetailsModification[].class);

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
            assertEquals(3, getApprovals(userToken, c.getClientId()).length);
        }

        //change the secret, and we know don't the old secret
        for (ClientDetailsModification c : clients) {
            c.setClientSecret("secret");
            c.setAction(c.UPDATE_SECRET);
        }
        modifyClientsPost = post("/oauth/clients/tx/modify")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(toString(clients));
        result = getMockMvc().perform(modifyClientsPost);
        result.andExpect(status().isOk());

        clients = (ClientDetailsModification[])arrayFromString(result.andReturn().getResponse().getContentAsString(), ClientDetailsModification[].class);

        //check that we still have approvals for each client
        for (ClientDetailsModification c : clients) {
            assertFalse(c.isApprovalsDeleted());
            String userToken = testClient.getUserOAuthAccessToken(
                    c.getClientId(),
                    "secret",
                    testUser.getUserName(),
                    testPassword,
                    "oauth.approvals");
            assertEquals(3, getApprovals(userToken,c.getClientId()).length);
        }
    }

    @Test
    public void testClientsAdminPermissions() throws Exception {
        ClientDetails adminsClient = createClientAdminsClient(adminToken);

        //create clients
        ClientDetailsModification[] clients = createBaseClients(3, Arrays.asList("client_credentials","refresh_token"));
        for (ClientDetailsModification c : clients) {
            c.setScope(Collections.singletonList("oauth.approvals"));
            c.setAction(c.ADD);
        }

        String token = testClient.getClientCredentialsOAuthAccessToken(
            adminsClient.getClientId(),
            "secret",
            "clients.admin");

        MockHttpServletRequestBuilder modifyClientsPost = post("/oauth/clients/tx/modify")
                .header("Authorization", "Bearer " + token)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(toString(clients));
        ResultActions result = getMockMvc().perform(modifyClientsPost);
        result.andExpect(status().isOk());
    }

    @Test
    public void testNonClientsAdminPermissions() throws Exception {
        ClientDetails adminsClient = createReadWriteClient(adminToken);

        //create clients
        ClientDetailsModification[] clients = createBaseClients(3, Arrays.asList("client_credentials","refresh_token"));
        for (ClientDetailsModification c : clients) {
            c.setScope(Collections.singletonList("oauth.approvals"));
            c.setAction(c.ADD);
        }

        String token = testClient.getClientCredentialsOAuthAccessToken(
            adminsClient.getClientId(),
            "secret",
            "clients.write");

        MockHttpServletRequestBuilder modifyClientsPost = post("/oauth/clients/tx/modify")
                .header("Authorization", "Bearer " + token)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(toString(clients));
        ResultActions result = getMockMvc().perform(modifyClientsPost);
        result.andExpect(status().isForbidden());
    }


    @Test
    public void testCreateAsAdminPermissions() throws Exception {
        ClientDetails adminsClient = createClientAdminsClient(adminToken);

        //create clients
        ClientDetailsModification[] clients = createBaseClients(1, Arrays.asList("client_credentials","refresh_token"));
        for (ClientDetailsModification c : clients) {
            c.setScope(Collections.singletonList("oauth.approvals"));
            c.setAction(c.ADD);
        }

        String token = testClient.getClientCredentialsOAuthAccessToken(
            adminsClient.getClientId(),
            "secret",
            "clients.admin");

        MockHttpServletRequestBuilder modifyClientsPost = post("/oauth/clients")
                .header("Authorization", "Bearer " + token)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(toString(clients[0]));
        ResultActions result = getMockMvc().perform(modifyClientsPost);
        result.andExpect(status().isCreated());
    }

    @Test
    public void testCreateAsReadPermissions() throws Exception {
        ClientDetails adminsClient = createReadWriteClient(adminToken);

        //create clients
        ClientDetailsModification[] clients = createBaseClients(1, Arrays.asList("client_credentials","refresh_token"));
        for (ClientDetailsModification c : clients) {
            c.setScope(Collections.singletonList("oauth.approvals"));
            c.setAction(c.ADD);
        }

        String token = testClient.getClientCredentialsOAuthAccessToken(
            adminsClient.getClientId(),
            "secret",
            "clients.read");

        MockHttpServletRequestBuilder modifyClientsPost = post("/oauth/clients")
                .header("Authorization", "Bearer " + token)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(toString(clients[0]));
        ResultActions result = getMockMvc().perform(modifyClientsPost);
        result.andExpect(status().isForbidden());
    }

    @Test
    public void testCreateAsWritePermissions() throws Exception {
        ClientDetails adminsClient = createReadWriteClient(adminToken);

        //create clients
        ClientDetailsModification[] clients = createBaseClients(1, Arrays.asList("client_credentials", "refresh_token"));
        for (ClientDetailsModification c : clients) {
            c.setScope(Collections.singletonList("oauth.approvals"));
            c.setAction(c.ADD);
        }

        String token = testClient.getClientCredentialsOAuthAccessToken(
            adminsClient.getClientId(),
            "secret",
            "clients.write");

        MockHttpServletRequestBuilder modifyClientsPost = post("/oauth/clients")
                .header("Authorization", "Bearer " + token)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(toString(clients[0]));
        ResultActions result = getMockMvc().perform(modifyClientsPost);
        result.andExpect(status().isCreated());
    }

    @Test
    public void testGetClientDetailsSortedByLastModified() throws Exception{

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

        MvcResult result = getMockMvc().perform(get).andExpect(status().isOk()).andReturn();
        String body = result.getResponse().getContentAsString();

        Collection<BaseClientDetails> clientDetails = JsonUtils.readValue(body, new TypeReference<SearchResults<BaseClientDetails>>() {
        }).getResources();

        assertNotNull(clientDetails);

        Date lastDate = null;

        for(ClientDetails clientDetail : clientDetails){
            assertTrue(clientDetail.getAdditionalInformation().containsKey("lastModified"));

            Date currentDate = JsonUtils.convertValue(clientDetail.getAdditionalInformation().get("lastModified"), Date.class);

            if(lastDate != null){
                assertTrue(currentDate.getTime() <= lastDate.getTime());
            }

            lastDate = currentDate;
        }
    }


    @Test
    public void testClientWithDotInID() throws Exception {
        ClientDetails details = createClient(adminToken, "testclient", Collections.singleton("client_credentials"));
        ClientDetails detailsv2 = createClient(adminToken, "testclient.v2", Collections.singleton("client_credentials"));
        assertEquals("testclient.v2", detailsv2.getClientId());
    }

    @Test
    public void testPutClientModifyAuthorities() throws Exception {
        ClientDetails client = createClient(adminToken, "testClientForModifyAuthorities", Collections.singleton("client_credentials"));

        BaseClientDetails modified = new BaseClientDetails(client);
        modified.setAuthorities(Collections.singleton((GrantedAuthority) () -> "newAuthority"));

        MockHttpServletRequestBuilder put = put("/oauth/clients/" + client.getClientId())
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(modified));
        MvcResult result = getMockMvc().perform(put).andExpect(status().isOk()).andReturn();

        client = getClient(client.getClientId());
        assertThat(client.getAuthorities(), iterableWithSize(1));
        GrantedAuthority authority = Iterables.get(client.getAuthorities(), 0);
        assertEquals("newAuthority", authority.getAuthority());
    }

    @Test
    public void testPutClientModifyAccessTokenValidity() throws Exception {
        ClientDetails client = createClient(adminToken, "testClientForModifyAccessTokenValidity", Collections.singleton("client_credentials"));

        BaseClientDetails modified = new BaseClientDetails(client);
        modified.setAccessTokenValiditySeconds(73);

        MockHttpServletRequestBuilder put = put("/oauth/clients/" + client.getClientId())
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(modified));
        MvcResult result = getMockMvc().perform(put).andExpect(status().isOk()).andReturn();

        client = getClient(client.getClientId());
        assertThat(client.getAccessTokenValiditySeconds(), is(73));
    }

    @Test
    public void testPutClientModifyName() throws Exception {
        ClientDetails client = createClient(adminToken, "testClientForModifyName", Collections.singleton("client_credentials"));

        Map<String, Object> requestBody = JsonUtils.readValue(JsonUtils.writeValueAsString(new BaseClientDetails(client)), new TypeReference<Map<String, Object>>() {});
        requestBody.put("name", "New Client Name");

        MockHttpServletRequestBuilder put = put("/oauth/clients/" + client.getClientId())
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(requestBody));
        MvcResult result = getMockMvc().perform(put).andExpect(status().isOk()).andReturn();

        MockHttpServletResponse response = getClientHttpResponse(client.getClientId());
        Map<String, Object> map = JsonUtils.readValue(response.getContentAsString(), new TypeReference<Map<String, Object>>() {});
        assertThat(map, hasEntry(is("name"), PredicateMatcher.is(value -> value.equals("New Client Name"))));

        client = getClientResponseAsClientDetails(response);
        assertThat(client.getAdditionalInformation(), hasEntry(is("name"), PredicateMatcher.is(value -> value.equals("New Client Name"))));
    }

    private Approval[] getApprovals(String token, String clientId) throws Exception {
        JdbcApprovalStore endpoint = getWebApplicationContext().getBean(JdbcApprovalStore.class);
        return endpoint.getApprovalsForClient(clientId).toArray(new Approval[0]);
    }


    private Approval[] addApprovals(String token, String clientId) throws Exception {
        Date oneMinuteAgo = new Date(System.currentTimeMillis() - 60000);
        Date expiresAt = new Date(System.currentTimeMillis() + 60000);
        Approval[] approvals = new Approval[] {
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

        MockHttpServletRequestBuilder put = put("/approvals/"+clientId)
            .header("Authorization", "Bearer " + token)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content(toString(approvals));
        getMockMvc().perform(put).andExpect(status().isOk());
        return approvals;
    }
}
