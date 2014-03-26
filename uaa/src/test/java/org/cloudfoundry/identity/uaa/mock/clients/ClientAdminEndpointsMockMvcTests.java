package org.cloudfoundry.identity.uaa.mock.clients;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Arrays;
import java.util.Collections;
import java.util.Date;

import org.cloudfoundry.identity.uaa.config.YamlServletProfileInitializer;
import org.cloudfoundry.identity.uaa.oauth.InvalidClientDetailsException;
import org.cloudfoundry.identity.uaa.oauth.approval.Approval;
import org.cloudfoundry.identity.uaa.oauth.approval.Approval.ApprovalStatus;
import org.cloudfoundry.identity.uaa.oauth.client.ClientDetailsModification;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.codehaus.jackson.map.ObjectMapper;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
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

import com.googlecode.flyway.core.Flyway;


public class ClientAdminEndpointsMockMvcTests {
    private XmlWebApplicationContext webApplicationContext;
    private MockMvc mockMvc;
    private String adminToken = null;
    private TestClient testClient = null;
    private TestAccounts testAccounts = null;

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

        testClient = new TestClient(mockMvc);
        testAccounts = UaaTestAccounts.standard(null);
        adminToken = testClient.getOAuthAccessToken(
                        testAccounts.getAdminClientId(), 
                        testAccounts.getAdminClientSecret(), 
                        "client_credentials",
                        "clients.read clients.write clients.secret");
        
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
    }

    @Test
    public void testCreateClientsTxSuccess() throws Exception {
        BaseClientDetails[] details = createBaseClients(5, null);
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
    }

    @Test
    public void testUpdateClientsTxSuccess() throws Exception {
        BaseClientDetails[] details = new BaseClientDetails[5];
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
    }

    @Test
    public void testUpdateClientsTxInvalidId() throws Exception {
        BaseClientDetails[] details = new BaseClientDetails[5];
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
    }

    @Test
    public void testDeleteClientsTxSuccess() throws Exception {
        BaseClientDetails[] details = new BaseClientDetails[5];
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
    }

    @Test
    public void testDeleteClientsTxRollbackInvalidId() throws Exception {
        BaseClientDetails[] details = new BaseClientDetails[5];
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
    }

    @Test
    public void testAddUpdateDeleteClientsTxSuccess() throws Exception {
        ClientDetailsModification[] details = new ClientDetailsModification[15];
        for (int i=0; i<5; i++) {
            details[i] = (ClientDetailsModification)createClient(adminToken,null,null);
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


        MockHttpServletRequestBuilder modifyClientsPost = post("/oauth/clients/tx/modify")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(toString(details));
        ResultActions result = mockMvc.perform(modifyClientsPost);
        result.andExpect(status().isOk());

        for (int i=0; i<5; i++) {
            ClientDetails c = getClient(details[i].getClientId());
            assertNotNull(c);
            assertEquals(new Integer(120), c.getRefreshTokenValiditySeconds());

        }
        for (int i=5; i<10; i++) {
            ClientDetails c = getClient(details[i].getClientId());
            assertNull(c);
        }
        for (int i=10; i<15; i++) {
            ClientDetails c = getClient(details[i].getClientId());
            assertNotNull(c);
            assertNull(c.getRefreshTokenValiditySeconds());
        }
    }

    @Test
    public void testAddUpdateDeleteClientsTxDeleteFailedRollback() throws Exception {
        ClientDetailsModification[] details = new ClientDetailsModification[15];
        for (int i=0; i<5; i++) {
            details[i] = (ClientDetailsModification)createClient(adminToken,null,null);
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
                        .content(toString(new ClientDetails[] {details}));
        ResultActions result = mockMvc.perform(deleteClientsPost);
        result.andExpect(status().isOk());
        approvals = getApprovals(userToken, details.getClientId());
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
        approvals = getApprovals(userToken, details.getClientId());
        assertEquals(0, approvals.length);
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
        
        MockHttpServletRequestBuilder put = put("/approvals")
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


    private ClientDetailsModification createBaseClient(String id, String grantTypes) {
        if (id==null) {
            id = new RandomValueStringGenerator().generate();
        }
        if (grantTypes==null) {
            grantTypes = "client_credentials";
        }
        ClientDetailsModification client = new ClientDetailsModification(id, "", "foo,bar,oauth.approvals", grantTypes, "uaa.none");
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
