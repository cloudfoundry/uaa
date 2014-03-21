package org.cloudfoundry.identity.uaa.mock.clients;

import com.googlecode.flyway.core.Flyway;

import org.cloudfoundry.identity.uaa.config.YamlServletProfileInitializer;
import org.cloudfoundry.identity.uaa.oauth.InvalidClientDetailsException;
import org.cloudfoundry.identity.uaa.oauth.client.ClientDetailsModification;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.codehaus.jackson.map.ObjectMapper;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.BaseClientDetails;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.util.StringUtils;
import org.springframework.web.context.support.XmlWebApplicationContext;

import java.util.Arrays;
import java.util.Collections;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;


public class ClientAdminEndpointsMockMvcTests {
    private XmlWebApplicationContext webApplicationContext;
    private MockMvc mockMvc;
    private String adminToken = null;

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

        TestClient testClient = new TestClient(mockMvc);
        adminToken = testClient.getOAuthAccessToken("admin", "adminsecret", "client_credentials",
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
        ClientDetails[] clients = arrayFromString(result.andReturn().getResponse().getContentAsString());
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
        ClientDetails[] clients = arrayFromString(result.andReturn().getResponse().getContentAsString());
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
            return fromString(body);
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
        ClientDetailsModification client = new ClientDetailsModification(id, "", "foo,bar", grantTypes, "uaa.none");
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

    private String toString(ClientDetails client) throws Exception {
        return new ObjectMapper().writeValueAsString(client);
    }

    private String toString(ClientDetails[] clients) throws Exception {
        return new ObjectMapper().writeValueAsString(clients);
    }

    private ClientDetails fromString(String client) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        return (ClientDetails)mapper.readValue(client, ClientDetailsModification.class);
    }

    private ClientDetails[] arrayFromString(String clients) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        return (ClientDetails[])mapper.readValue(clients, ClientDetailsModification[].class);
    }

}
