package org.cloudfoundry.identity.uaa.mock.clients;

import com.googlecode.flyway.core.Flyway;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.audit.event.AbstractUaaEvent;
import org.cloudfoundry.identity.uaa.config.YamlServletProfileInitializer;
import org.cloudfoundry.identity.uaa.oauth.InvalidClientDetailsException;
import org.cloudfoundry.identity.uaa.oauth.SecretChangeRequest;
import org.cloudfoundry.identity.uaa.oauth.approval.Approval;
import org.cloudfoundry.identity.uaa.oauth.approval.Approval.ApprovalStatus;
import org.cloudfoundry.identity.uaa.oauth.client.ClientDetailsModification;
import org.cloudfoundry.identity.uaa.oauth.event.ClientAdminEventPublisher;
import org.cloudfoundry.identity.uaa.rest.SearchResults;
import org.cloudfoundry.identity.uaa.scim.domain.common.ScimGroupInterface;
import org.cloudfoundry.identity.uaa.scim.domain.common.ScimGroupMemberInterface;
import org.cloudfoundry.identity.uaa.scim.domain.standard.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.domain.standard.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.endpoints.ScimGroupEndpoints;
import org.cloudfoundry.identity.uaa.scim.endpoints.ScimUserEndpoints;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.codehaus.jackson.map.ObjectMapper;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.oauth2.client.test.TestAccounts;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.BaseClientDetails;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.util.StringUtils;
import org.springframework.web.context.support.XmlWebApplicationContext;

import javax.servlet.http.HttpServletResponse;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;


public class ClientAdminEndpointsMockMvcTests {
    private XmlWebApplicationContext webApplicationContext;
    private MockMvc mockMvc;
    private String adminToken = null;
    private TestClient testClient = null;
    private UaaTestAccounts testAccounts = null;
    private String adminUserToken = null;
    private ScimUserEndpoints scimUserEndpoints = null;
    private ScimGroupEndpoints scimGroupEndpoints = null;
    private ApplicationEventPublisher applicationEventPublisher = null;
    private ArgumentCaptor<AbstractUaaEvent> captor = null;

    @Before
    public void setUp() throws Exception {
        webApplicationContext = new XmlWebApplicationContext();
        webApplicationContext.setServletContext(new MockServletContext());
        webApplicationContext.setConfigLocation("file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        new YamlServletProfileInitializer().initialize(webApplicationContext);
        webApplicationContext.refresh();
        FilterChainProxy springSecurityFilterChain = webApplicationContext.getBean(FilterChainProxy.class);

        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).addFilter(springSecurityFilterChain)
                .build();

        scimUserEndpoints = webApplicationContext.getBean(ScimUserEndpoints.class);
        scimGroupEndpoints = webApplicationContext.getBean(ScimGroupEndpoints.class);

        testClient = new TestClient(mockMvc);
        testAccounts = UaaTestAccounts.standard(null);
        adminToken = testClient.getOAuthAccessToken(
                        testAccounts.getAdminClientId(),
                        testAccounts.getAdminClientSecret(),
                        "client_credentials",
                        "clients.admin clients.read clients.write clients.secret");

        applicationEventPublisher = mock(ApplicationEventPublisher.class);
        ClientAdminEventPublisher eventPublisher = (ClientAdminEventPublisher)webApplicationContext.getBean("clientAdminEventPublisher");
        eventPublisher.setApplicationEventPublisher(applicationEventPublisher);
        captor = ArgumentCaptor.forClass(AbstractUaaEvent.class);

    }

    private void setupAdminUserToken() throws Exception {
        HttpServletResponse mockResponse = mock(HttpServletResponse.class);


        SearchResults<Map<String, Object>> marissa = (SearchResults<Map<String, Object>>)scimUserEndpoints.findUsers("id,userName", "userName eq '" + testAccounts.getUserName() + "'", "userName", "asc", 0, 1);
        String marissaId = (String)marissa.getResources().iterator().next().get("id");

        //add marissa to uaa.admin
        SearchResults<Map<String, Object>> uaaAdmin = (SearchResults<Map<String, Object>>) scimGroupEndpoints.listGroups("id,displayName", "displayName eq 'uaa.admin'", "displayName", "asc", 1, 1);
        String groupId = (String)uaaAdmin.getResources().iterator().next().get("id");
        ScimGroupInterface group = scimGroupEndpoints.getGroup(groupId, mockResponse);
        ScimGroupMemberInterface gm = new ScimGroupMember(marissaId, ScimGroupMemberInterface.Type.USER, Arrays.asList(ScimGroupMemberInterface.Role.MEMBER));
        ((List<ScimGroupMemberInterface>) group.getMembers()).add(gm);
        scimGroupEndpoints.updateGroup(group, groupId, String.valueOf(group.getVersion()), mockResponse);

        //add marissa to clients.write
        uaaAdmin = (SearchResults<Map<String, Object>>) scimGroupEndpoints.listGroups("id,displayName", "displayName eq 'clients.write'", "displayName", "asc", 1, 1);
        groupId = (String)uaaAdmin.getResources().iterator().next().get("id");
        group = scimGroupEndpoints.getGroup(groupId, mockResponse);
        gm = new ScimGroupMember(marissaId, ScimGroupMemberInterface.Type.USER, Arrays.asList(ScimGroupMemberInterface.Role.MEMBER));
        ((List<ScimGroupMemberInterface>) group.getMembers()).add(gm);
        scimGroupEndpoints.updateGroup(group, groupId, String.valueOf(group.getVersion()), mockResponse);

        //add marissa to clients.read
        uaaAdmin = (SearchResults<Map<String, Object>>) scimGroupEndpoints.listGroups("id,displayName", "displayName eq 'clients.read'", "displayName", "asc", 1, 1);
        groupId = (String)uaaAdmin.getResources().iterator().next().get("id");
        group = scimGroupEndpoints.getGroup(groupId, mockResponse);
        gm = new ScimGroupMember(marissaId, ScimGroupMemberInterface.Type.USER, Arrays.asList(ScimGroupMemberInterface.Role.MEMBER));
        ((List<ScimGroupMemberInterface>) group.getMembers()).add(gm);
        scimGroupEndpoints.updateGroup(group, groupId, String.valueOf(group.getVersion()), mockResponse);

        ClientDetails adminClient = createAdminClient(adminToken);

        adminUserToken = testClient.getUserOAuthAccessToken(adminClient.getClientId(),
                                                            "secret",
                                                            testAccounts.getUserName(),
                                                            testAccounts.getPassword(),
                                                            "uaa.admin,clients.read,clients.write");
    }

    @After
    public void tearDown() throws Exception {
        Flyway flyway = webApplicationContext.getBean(Flyway.class);
        flyway.clean();
        webApplicationContext.close();
    }

    @Test
    public void testCreateClient() throws Exception {
        createClient(adminToken, new RandomValueStringGenerator().generate(), "client_credentials");
        verify(applicationEventPublisher, times(1)).publishEvent(captor.capture());
        assertEquals(AuditEventType.ClientCreateSuccess, captor.getValue().getAuditEvent().getType());
    }

    @Test
    public void testCreateClientAsAdminUser() throws Exception {
        setupAdminUserToken();
        createClient(adminUserToken, new RandomValueStringGenerator().generate(), "client_credentials");
        verify(applicationEventPublisher, times(2)).publishEvent(captor.capture());
        for (AbstractUaaEvent event : captor.getAllValues()) {
            assertEquals(AuditEventType.ClientCreateSuccess, event.getAuditEvent().getType());
        }
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
        ResultActions result = mockMvc.perform(createClientPost);
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
        mockMvc.perform(createClientPost).andExpect(status().isConflict());
        for (ClientDetails client : details) {
            assertNull(getClient(client.getClientId()));
        }
        verify(applicationEventPublisher, times(0)).publishEvent(captor.capture());
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
        mockMvc.perform(createClientPost).andExpect(status().isBadRequest());
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
        ResultActions result = mockMvc.perform(updateClientPut);
        result.andExpect(status().isOk());
        ClientDetails[] clients = clientArrayFromString(result.andReturn().getResponse().getContentAsString());
        for (ClientDetails client : clients) {
            assertNotNull(getClient(client.getClientId()));
            assertEquals(new Integer(120), client.getRefreshTokenValiditySeconds());
        }
        //create and then update events
        verify(applicationEventPublisher, times(count*2)).publishEvent(captor.capture());
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
        ResultActions result = mockMvc.perform(deleteClientsPost);
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
        ResultActions result = mockMvc.perform(deleteClientsPost);
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
        ResultActions result = mockMvc.perform(modifyClientsPost);
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
                    break;
                }
                case 2 : {
                    //the 11-15 events are update
                    assertEquals(AuditEventType.ClientUpdateSuccess, event.getAuditEvent().getType());
                    break;
                }
                case 3 : {
                    //the 16-20 events are deletes
                    assertEquals(AuditEventType.ClientDeleteSuccess, event.getAuditEvent().getType());
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
            details[i] = (ClientDetailsModification)createClient(adminToken,null,"password");
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
                testAccounts.getUserName(),
                testAccounts.getPassword(),
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
        ResultActions result = mockMvc.perform(modifyClientsPost);
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
        ClientDetails details = createClient(adminToken, new RandomValueStringGenerator().generate(), "password");
        String userToken = testClient.getUserOAuthAccessToken(
                details.getClientId(),
                "secret",
                testAccounts.getUserName(),
                testAccounts.getPassword(),
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
        ResultActions result = mockMvc.perform(deleteClientsPost);
        result.andExpect(status().isOk());


        ClientDetailsModification[] deleted = (ClientDetailsModification[]) arrayFromString(result.andReturn().getResponse().getContentAsString(), ClientDetailsModification[].class);
        assertTrue(deleted[0].isApprovalsDeleted());
        verify(applicationEventPublisher, times(2)).publishEvent(captor.capture());

        ClientDetails approvalsClient = createApprovalsLoginClient(adminToken);
        String loginToken = testClient.getUserOAuthAccessToken(
                approvalsClient.getClientId(),
                "secret",
                testAccounts.getUserName(),
                testAccounts.getPassword(),
                "oauth.approvals");

        approvals = getApprovals(loginToken, details.getClientId());
        assertEquals(0, approvals.length);

    }

    @Test
    public void testApprovalsAreDeleted2() throws Exception {
        ClientDetails details = createClient(adminToken, new RandomValueStringGenerator().generate(), "password");
        String userToken = testClient.getUserOAuthAccessToken(
                            details.getClientId(),
                            "secret",
                            testAccounts.getUserName(),
                            testAccounts.getPassword(),
                            "oauth.approvals");
        Approval[] approvals = getApprovals(userToken, details.getClientId());
        assertEquals(0, approvals.length);
        addApprovals(userToken, details.getClientId());
        approvals = getApprovals(userToken, details.getClientId());
        assertEquals(3, approvals.length);

        MockHttpServletRequestBuilder deleteClientsPost = delete("/oauth/clients/"+details.getClientId())
                        .header("Authorization", "Bearer " + adminToken)
                        .accept(APPLICATION_JSON);
        ResultActions result = mockMvc.perform(deleteClientsPost);
        result.andExpect(status().isOk());

        ClientDetails approvalsClient = createApprovalsLoginClient(adminToken);
        String loginToken = testClient.getUserOAuthAccessToken(
                approvalsClient.getClientId(),
                "secret",
                testAccounts.getUserName(),
                testAccounts.getPassword(),
                "oauth.approvals");

        approvals = getApprovals(loginToken, details.getClientId());
        assertEquals(0, approvals.length);
    }

    @Test
    public void testModifyApprovalsAreDeleted() throws Exception {
        ClientDetails details = createClient(adminToken, new RandomValueStringGenerator().generate(), "password");
        ((ClientDetailsModification)details).setAction(ClientDetailsModification.DELETE);
        String userToken = testClient.getUserOAuthAccessToken(
            details.getClientId(),
            "secret",
            testAccounts.getUserName(),
            testAccounts.getPassword(),
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
        ResultActions result = mockMvc.perform(deleteClientsPost);
        result.andExpect(status().isOk());
        ClientDetailsModification[] deleted = (ClientDetailsModification[]) arrayFromString(result.andReturn().getResponse().getContentAsString(), ClientDetailsModification[].class);
        assertTrue(deleted[0].isApprovalsDeleted());
        verify(applicationEventPublisher, times(2)).publishEvent(captor.capture());

        ClientDetails approvalsClient = createApprovalsLoginClient(adminToken);
        String loginToken = testClient.getUserOAuthAccessToken(
                approvalsClient.getClientId(),
                "secret",
                testAccounts.getUserName(),
                testAccounts.getPassword(),
                "oauth.approvals");
        approvals = getApprovals(loginToken, details.getClientId());
        assertEquals(0, approvals.length);
    }

    @Test
    public void testSecretChangeTxApprovalsNotDeleted() throws Exception {
        int count = 3;
        //create clients
        ClientDetailsModification[] clients = createBaseClients(count, "client_credentials,password");
        for (ClientDetailsModification c : clients) {
            c.setAction(c.ADD);
        }
        MockHttpServletRequestBuilder modifyClientsPost = post("/oauth/clients/tx/modify")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(toString(clients));
        ResultActions result = mockMvc.perform(modifyClientsPost);
        result.andExpect(status().isOk());

        //add approvals to the client
        for (ClientDetailsModification c : clients) {
            String userToken = testClient.getUserOAuthAccessToken(
                    c.getClientId(),
                    "secret",
                    testAccounts.getUserName(),
                    testAccounts.getPassword(),
                    "oauth.approvals");
            addApprovals(userToken, c.getClientId());
        }

        //verify approvals to the client
        for (ClientDetailsModification c : clients) {
            String userToken = testClient.getUserOAuthAccessToken(
                    c.getClientId(),
                    "secret",
                    testAccounts.getUserName(),
                    testAccounts.getPassword(),
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
        result = mockMvc.perform(modifyClientsPost);
        result.andExpect(status().isOk());

        clients = (ClientDetailsModification[])arrayFromString(result.andReturn().getResponse().getContentAsString(), ClientDetailsModification[].class);

        //check that we still have approvals for each client
        ClientDetails approvalsClient = createApprovalsLoginClient(adminToken);

        for (ClientDetailsModification c : clients) {
            String loginToken = testClient.getUserOAuthAccessToken(
                    approvalsClient.getClientId(),
                    "secret",
                    testAccounts.getUserName(),
                    testAccounts.getPassword(),
                    "oauth.approvals");
            assertEquals(3, getApprovals(loginToken,c.getClientId()).length);
            assertFalse(c.isApprovalsDeleted());
        }

    }

    @Test
    public void testSecretChangeModifyTxApprovalsDeleted() throws Exception {
        int count = 3;
        //create clients
        ClientDetailsModification[] clients = createBaseClients(count, "client_credentials,password");
        for (ClientDetailsModification c : clients) {
            c.setAction(c.ADD);
        }
        MockHttpServletRequestBuilder modifyClientsPost = post("/oauth/clients/tx/modify")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(toString(clients));
        ResultActions result = mockMvc.perform(modifyClientsPost);
        result.andExpect(status().isOk());

        clients = (ClientDetailsModification[])arrayFromString(result.andReturn().getResponse().getContentAsString(), ClientDetailsModification[].class);

        //add approvals to the client
        for (ClientDetailsModification c : clients) {
            String userToken = testClient.getUserOAuthAccessToken(
                    c.getClientId(),
                    "secret",
                    testAccounts.getUserName(),
                    testAccounts.getPassword(),
                    "oauth.approvals");
            addApprovals(userToken, c.getClientId());
        }

        //verify approvals to the client
        for (ClientDetailsModification c : clients) {
            String userToken = testClient.getUserOAuthAccessToken(
                    c.getClientId(),
                    "secret",
                    testAccounts.getUserName(),
                    testAccounts.getPassword(),
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
        result = mockMvc.perform(modifyClientsPost);
        result.andExpect(status().isOk());
        clients = (ClientDetailsModification[])arrayFromString(result.andReturn().getResponse().getContentAsString(), ClientDetailsModification[].class);

        //check that we deleted approvals for each client
        for (ClientDetailsModification c : clients) {
            String userToken = testClient.getUserOAuthAccessToken(
                    c.getClientId(),
                    "secret2",
                    testAccounts.getUserName(),
                    testAccounts.getPassword(),
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
                }
            }

            index++;
        }
    }

    @Test
    public void testSecretChangeModifyTxApprovalsNotDeleted() throws Exception {
        //create clients
        ClientDetailsModification[] clients = createBaseClients(3, "client_credentials,password");
        for (ClientDetailsModification c : clients) {
            c.setAction(c.ADD);
        }
        MockHttpServletRequestBuilder modifyClientsPost = post("/oauth/clients/tx/modify")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(toString(clients));
        ResultActions result = mockMvc.perform(modifyClientsPost);
        result.andExpect(status().isOk());

        clients = (ClientDetailsModification[])arrayFromString(result.andReturn().getResponse().getContentAsString(), ClientDetailsModification[].class);

        //add approvals to the client
        for (ClientDetailsModification c : clients) {
            String userToken = testClient.getUserOAuthAccessToken(
                    c.getClientId(),
                    "secret",
                    testAccounts.getUserName(),
                    testAccounts.getPassword(),
                    "oauth.approvals");
            addApprovals(userToken, c.getClientId());
        }

        //verify approvals to the client
        for (ClientDetailsModification c : clients) {
            String userToken = testClient.getUserOAuthAccessToken(
                    c.getClientId(),
                    "secret",
                    testAccounts.getUserName(),
                    testAccounts.getPassword(),
                    "oauth.approvals");
            assertEquals(3, getApprovals(userToken,c.getClientId()).length);
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
        result = mockMvc.perform(modifyClientsPost);
        result.andExpect(status().isOk());

        clients = (ClientDetailsModification[])arrayFromString(result.andReturn().getResponse().getContentAsString(), ClientDetailsModification[].class);

        //check that we still have approvals for each client
        for (ClientDetailsModification c : clients) {
            assertFalse(c.isApprovalsDeleted());
            String userToken = testClient.getUserOAuthAccessToken(
                    c.getClientId(),
                    "secret",
                    testAccounts.getUserName(),
                    testAccounts.getPassword(),
                    "oauth.approvals");
            assertEquals(3, getApprovals(userToken,c.getClientId()).length);
        }
    }

    @Test
    public void testClientsAdminPermissions() throws Exception {
        ClientDetails adminsClient = createClientAdminsClient(adminToken);

        //create clients
        ClientDetailsModification[] clients = createBaseClients(3, "client_credentials,refresh_token");
        for (ClientDetailsModification c : clients) {
            c.setScope(Collections.singletonList("oauth.approvals"));
            c.setAction(c.ADD);
        }

        String token = testClient.getOAuthAccessToken(
                adminsClient.getClientId(),
                "secret",
                "client_credentials",
                "clients.admin");

        MockHttpServletRequestBuilder modifyClientsPost = post("/oauth/clients/tx/modify")
                .header("Authorization", "Bearer " + token)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(toString(clients));
        ResultActions result = mockMvc.perform(modifyClientsPost);
        result.andExpect(status().isOk());
    }

    @Test
    public void testNonClientsAdminPermissions() throws Exception {
        ClientDetails adminsClient = createReadWriteClient(adminToken);

        //create clients
        ClientDetailsModification[] clients = createBaseClients(3, "client_credentials,refresh_token");
        for (ClientDetailsModification c : clients) {
            c.setScope(Collections.singletonList("oauth.approvals"));
            c.setAction(c.ADD);
        }

        String token = testClient.getOAuthAccessToken(
                adminsClient.getClientId(),
                "secret",
                "client_credentials",
                "clients.write");

        MockHttpServletRequestBuilder modifyClientsPost = post("/oauth/clients/tx/modify")
                .header("Authorization", "Bearer " + token)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(toString(clients));
        ResultActions result = mockMvc.perform(modifyClientsPost);
        result.andExpect(status().isForbidden());
    }


    @Test
    public void testCreateAsAdminPermissions() throws Exception {
        ClientDetails adminsClient = createClientAdminsClient(adminToken);

        //create clients
        ClientDetailsModification[] clients = createBaseClients(1, "client_credentials,refresh_token");
        for (ClientDetailsModification c : clients) {
            c.setScope(Collections.singletonList("oauth.approvals"));
            c.setAction(c.ADD);
        }

        String token = testClient.getOAuthAccessToken(
                adminsClient.getClientId(),
                "secret",
                "client_credentials",
                "clients.admin");

        MockHttpServletRequestBuilder modifyClientsPost = post("/oauth/clients")
                .header("Authorization", "Bearer " + token)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(toString(clients[0]));
        ResultActions result = mockMvc.perform(modifyClientsPost);
        result.andExpect(status().isCreated());
    }

    @Test
    public void testCreateAsReadPermissions() throws Exception {
        ClientDetails adminsClient = createReadWriteClient(adminToken);

        //create clients
        ClientDetailsModification[] clients = createBaseClients(1, "client_credentials,refresh_token");
        for (ClientDetailsModification c : clients) {
            c.setScope(Collections.singletonList("oauth.approvals"));
            c.setAction(c.ADD);
        }

        String token = testClient.getOAuthAccessToken(
                adminsClient.getClientId(),
                "secret",
                "client_credentials",
                "clients.read");

        MockHttpServletRequestBuilder modifyClientsPost = post("/oauth/clients")
                .header("Authorization", "Bearer " + token)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(toString(clients[0]));
        ResultActions result = mockMvc.perform(modifyClientsPost);
        result.andExpect(status().isForbidden());
    }

    @Test
    public void testCreateAsWritePermissions() throws Exception {
        ClientDetails adminsClient = createReadWriteClient(adminToken);

        //create clients
        ClientDetailsModification[] clients = createBaseClients(1, "client_credentials,refresh_token");
        for (ClientDetailsModification c : clients) {
            c.setScope(Collections.singletonList("oauth.approvals"));
            c.setAction(c.ADD);
        }

        String token = testClient.getOAuthAccessToken(
                adminsClient.getClientId(),
                "secret",
                "client_credentials",
                "clients.write");

        MockHttpServletRequestBuilder modifyClientsPost = post("/oauth/clients")
                .header("Authorization", "Bearer " + token)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(toString(clients[0]));
        ResultActions result = mockMvc.perform(modifyClientsPost);
        result.andExpect(status().isCreated());
    }


    private Approval[] getApprovals(String token, String clientId) throws Exception {
        String filter = "clientId eq '"+clientId+"'";

        MockHttpServletRequestBuilder get = get("/approvals")
                        .header("Authorization", "Bearer " + token)
                        .accept(APPLICATION_JSON)
                        .param("filter", filter);
        MvcResult result = mockMvc.perform(get).andExpect(status().isOk()).andReturn();
        String body = result.getResponse().getContentAsString();
        Approval[] approvals = (Approval[])arrayFromString(body, Approval[].class);
        return approvals;
    }


    private Approval[] addApprovals(String token, String clientId) throws Exception {
        Date oneMinuteAgo = new Date(System.currentTimeMillis() - 60000);
        Date expiresAt = new Date(System.currentTimeMillis() + 60000);
        Approval[] approvals = new Approval[] {
            new Approval(testAccounts.getUserName(), clientId, "cloud_controller.read", expiresAt, ApprovalStatus.APPROVED,oneMinuteAgo),
            new Approval(testAccounts.getUserName(), clientId, "openid", expiresAt, ApprovalStatus.APPROVED,oneMinuteAgo),
            new Approval(testAccounts.getUserName(), clientId, "password.write", expiresAt, ApprovalStatus.APPROVED,oneMinuteAgo)};

        MockHttpServletRequestBuilder put = put("/approvals/"+clientId)
            .header("Authorization", "Bearer " + token)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content(toString(approvals));
        mockMvc.perform(put).andExpect(status().isOk());
        return approvals;
    }

    private ClientDetails createClient(String token, String id, String grantTypes) throws Exception {
        BaseClientDetails client = createBaseClient(id,grantTypes);
        MockHttpServletRequestBuilder createClientPost = post("/oauth/clients")
                .header("Authorization", "Bearer " + token)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(toString(client));
        mockMvc.perform(createClientPost).andExpect(status().isCreated());
        return getClient(client.getClientId());
    }

    private ClientDetails getClient(String id) throws Exception {
        MockHttpServletRequestBuilder getClient = get("/oauth/clients/" + id)
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON);
        ResultActions result = mockMvc.perform(getClient);
        int responseCode = result.andReturn().getResponse().getStatus();
        HttpStatus status = HttpStatus.valueOf(responseCode);
        String body = result.andReturn().getResponse().getContentAsString();
        if (status == HttpStatus.OK) {
            return clientFromString(body);
        } else if ( status == HttpStatus.NOT_FOUND) {
            return null;
        } else {
            throw new InvalidClientDetailsException(status+" : "+body);
        }
    }

    private ClientDetails createClientAdminsClient(String token) throws Exception {
        String scopes = "oauth.approvals,clients.admin";
        BaseClientDetails client = createBaseClient(null, "password,client_credentials", scopes, scopes);
        MockHttpServletRequestBuilder createClientPost = post("/oauth/clients")
                .header("Authorization", "Bearer " + token)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(toString(client));
        mockMvc.perform(createClientPost).andExpect(status().isCreated());
        return getClient(client.getClientId());
    }

    private ClientDetails createReadWriteClient(String token) throws Exception {
        String scopes = "oauth.approvals,clients.read,clients.write";
        BaseClientDetails client = createBaseClient(null, "password,client_credentials", scopes, scopes);
        MockHttpServletRequestBuilder createClientPost = post("/oauth/clients")
                .header("Authorization", "Bearer " + token)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(toString(client));
        mockMvc.perform(createClientPost).andExpect(status().isCreated());
        return getClient(client.getClientId());
    }

    private ClientDetails createAdminClient(String token) throws Exception {
        String scopes = "uaa.admin,oauth.approvals,clients.read,clients.write";
        BaseClientDetails client = createBaseClient(null, "password,client_credentials", scopes, scopes);

        MockHttpServletRequestBuilder createClientPost = post("/oauth/clients")
                .header("Authorization", "Bearer " + token)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(toString(client));
        mockMvc.perform(createClientPost).andExpect(status().isCreated());
        return getClient(client.getClientId());
    }

    private ClientDetails createApprovalsLoginClient(String token) throws Exception {
        String scopes = "uaa.admin,oauth.approvals,oauth.login";
        BaseClientDetails client = createBaseClient(null, "password,client_credentials", scopes, scopes);

        MockHttpServletRequestBuilder createClientPost = post("/oauth/clients")
                .header("Authorization", "Bearer " + token)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(toString(client));
        mockMvc.perform(createClientPost).andExpect(status().isCreated());
        return getClient(client.getClientId());
    }




    private ClientDetailsModification createBaseClient(String id, String grantTypes) {
        return createBaseClient(id, grantTypes, "uaa.none", "foo,bar,oauth.approvals");
    }

    private ClientDetailsModification createBaseClient(String id, String grantTypes, String authorities, String scopes) {
        if (id==null) {
            id = new RandomValueStringGenerator().generate();
        }
        if (grantTypes==null) {
            grantTypes = "client_credentials";
        }
        ClientDetailsModification client = new ClientDetailsModification(id, "", scopes, grantTypes, authorities);
        client.setClientSecret("secret");
        client.setAdditionalInformation(Collections.<String, Object> singletonMap("foo", Arrays.asList("bar")));
        return client;
    }

    private ClientDetailsModification[] createBaseClients(int length, String grantTypes) {
        ClientDetailsModification[] result = new ClientDetailsModification[length];
        for (int i=0; i<result.length; i++) {
            result[i] = createBaseClient(null,grantTypes);
        }
        return result;
    }

    private String toString(Object client) throws Exception {
        return new ObjectMapper().writeValueAsString(client);
    }

    private String toString(Object[] clients) throws Exception {
        return new ObjectMapper().writeValueAsString(clients);
    }

    private ClientDetails clientFromString(String client) throws Exception {
        return (ClientDetails)fromString(client, ClientDetailsModification.class);
    }

    private Object fromString(String body, Class<?> clazz) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(body, clazz);
    }

    private ClientDetails[] clientArrayFromString(String clients) throws Exception {
        return (ClientDetails[])arrayFromString(clients, ClientDetailsModification[].class);
    }

    private Object[] arrayFromString(String body, Class<?> clazz) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        return (Object[])mapper.readValue(body, clazz);
    }


}
