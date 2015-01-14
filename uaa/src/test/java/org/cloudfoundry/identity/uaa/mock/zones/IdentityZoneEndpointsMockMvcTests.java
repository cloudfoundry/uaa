package org.cloudfoundry.identity.uaa.mock.zones;


import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.UUID;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import com.googlecode.flyway.core.Flyway;
import org.apache.commons.codec.binary.Base64;
import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMembershipManager;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.endpoints.ScimUserEndpoints;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.test.YamlServletProfileInitializerContextInitializer;
import org.cloudfoundry.identity.uaa.zone.IdentityProvider;
import org.cloudfoundry.identity.uaa.zone.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneCreationRequest;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.codehaus.jackson.map.ObjectMapper;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.util.StringUtils;
import org.springframework.web.context.support.XmlWebApplicationContext;

public class IdentityZoneEndpointsMockMvcTests {
    private static XmlWebApplicationContext webApplicationContext;
    private static MockMvc mockMvc;
    private static String identityAdminToken = null;
    private static TestClient testClient = null;

    @BeforeClass
    public static void setUp() throws Exception {
        webApplicationContext = new XmlWebApplicationContext();
        webApplicationContext.setServletContext(new MockServletContext());
        new YamlServletProfileInitializerContextInitializer().initializeContext(webApplicationContext, "uaa.yml,login.yml");
        webApplicationContext.setConfigLocation("file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        webApplicationContext.refresh();
        FilterChainProxy springSecurityFilterChain = webApplicationContext.getBean("springSecurityFilterChain", FilterChainProxy.class);

        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).addFilter(springSecurityFilterChain)
            .build();
        testClient = new TestClient(mockMvc);
        identityAdminToken = testClient.getClientCredentialsOAuthAccessToken(
                "identity",
                "identitysecret",
                "zones.create");
    }

    @AfterClass
    public static void tearDown() throws Exception {
        Flyway flyway = webApplicationContext.getBean(Flyway.class);
        flyway.clean();
        webApplicationContext.close();
    }
    @Before
    public void before() {
        IdentityZoneHolder.clear();
    }
    
    @After
    public void after() {
        IdentityZoneHolder.clear();
    }

    private ScimUser createUser(String scopes) throws Exception {

        ScimUserProvisioning userProvisioning = webApplicationContext.getBean(ScimUserProvisioning.class);
        ScimGroupProvisioning groupProvisioning = webApplicationContext.getBean(ScimGroupProvisioning.class);
        ScimGroupMembershipManager membershipManager = webApplicationContext.getBean(ScimGroupMembershipManager.class);
        ScimUserEndpoints userEndpoints = webApplicationContext.getBean(ScimUserEndpoints.class);

        //create the scope
        List<ScimGroup> scopeGroups = new LinkedList<>();
        for (String scope : StringUtils.commaDelimitedListToSet(scopes)) {
            ScimGroup group = new ScimGroup(new RandomValueStringGenerator().generate(), scope);
            scopeGroups.add(groupProvisioning.create(group));
        }

        //create the user
        String username = new RandomValueStringGenerator().generate();
        ScimUser user = new ScimUser(null, username, "Given", "Family");
        user.setPrimaryEmail(username+"@test.org");
        user.setOrigin(Origin.UAA);
        user = userProvisioning.createUser(user, "secret");

        //associate user with scope
        for (ScimGroup group : scopeGroups) {
            ScimGroupMember member = new ScimGroupMember(user.getId());
            membershipManager.addMember(group.getId(), member);
        }

        return (ScimUser)userEndpoints.findUsers(null, "username eq \""+user.getUserName()+"\"", null, "ascending", 0, 100).getResources().iterator().next();
    }

    @Test
    public void testCreateZone() throws Exception {
        String id = new RandomValueStringGenerator().generate();
        MvcResult result = createZone(id, HttpStatus.CREATED, identityAdminToken);
        IdentityZone zone = new ObjectMapper().readValue(result.getResponse().getContentAsByteArray(), IdentityZone.class);
        assertEquals(id, zone.getId());
        assertEquals(id, zone.getSubdomain());
    }

    @Test
    public void testCreateZoneWithoutID() throws Exception {
        String id = "";
        MvcResult result = createZone(id, HttpStatus.CREATED, identityAdminToken);
        IdentityZone zone = new ObjectMapper().readValue(result.getResponse().getContentAsByteArray(), IdentityZone.class);
        assertTrue(StringUtils.hasText(zone.getId()));
    }

    @Test
    public void testCreateDuplicateZoneReturns409() throws Exception {
        String id = new RandomValueStringGenerator().generate();
        createZone(id, HttpStatus.CREATED, identityAdminToken);
        createZone(id, HttpStatus.CONFLICT, identityAdminToken);
    }

    @Test
    public void testUpdateNonExistentReturns404() throws Exception {
        String id = new RandomValueStringGenerator().generate();
        updateZone(id, HttpStatus.NOT_FOUND, identityAdminToken);
    }

    @Test
    public void testUpdateExistentReturns200() throws Exception {
        String id = new RandomValueStringGenerator().generate();
        createZone(id, HttpStatus.CREATED, identityAdminToken);
        updateZone(id, HttpStatus.OK, identityAdminToken);
    }


    public MvcResult createZone(String id, HttpStatus expect, String token) throws Exception {
        IdentityZone identityZone = getIdentityZone(id);
        identityZone.setId(id);
        IdentityZoneCreationRequest creationRequest = new IdentityZoneCreationRequest();
        creationRequest.setIdentityZone(identityZone);
        return mockMvc.perform(post("/identity-zones")
            .header("Authorization", "Bearer " + token)
            .contentType(APPLICATION_JSON)
            .content(new ObjectMapper().writeValueAsString(creationRequest)))
                .andExpect(status().is(expect.value()))
                .andReturn();
    }

    public MvcResult updateZone(String id, HttpStatus expect, String token) throws Exception {
        IdentityZone identityZone = getIdentityZone(id);
        IdentityZoneCreationRequest creationRequest = new IdentityZoneCreationRequest();
        creationRequest.setIdentityZone(identityZone);
        return mockMvc.perform(put("/identity-zones/" + id)
            .header("Authorization", "Bearer " + token)
            .contentType(APPLICATION_JSON)
            .content(new ObjectMapper().writeValueAsString(creationRequest)))
            .andExpect(status().is(expect.value()))
            .andReturn();
    }



    @Test
    public void testCreateZoneAndIdentityProvider() throws Exception {
        IdentityZoneCreationRequest creationRequest = new IdentityZoneCreationRequest();
        String id = UUID.randomUUID().toString();
        IdentityZone identityZone = getIdentityZone(id);
        identityZone.setId(id);
        creationRequest.setIdentityZone(identityZone);
        
        mockMvc.perform(post("/identity-zones")
            .header("Authorization", "Bearer "+identityAdminToken)
            .contentType(APPLICATION_JSON)
            .content(new ObjectMapper().writeValueAsString(creationRequest)))
            .andExpect(status().isCreated())
            .andReturn();

        IdentityZoneHolder.set(identityZone);
        IdentityProviderProvisioning idpp = (IdentityProviderProvisioning) webApplicationContext.getBean("identityProviderProvisioning");
        IdentityProvider idp1 = idpp.retrieveByOrigin(Origin.UAA);
        
        IdentityZoneHolder.clear();
        IdentityProvider idp2 = idpp.retrieveByOrigin(Origin.UAA);
        assertNotEquals(idp1,  idp2);
    }

    private IdentityZone getIdentityZone(String subdomain) {
        IdentityZone identityZone = new IdentityZone();
        identityZone.setSubdomain(StringUtils.hasText(subdomain)?subdomain:new RandomValueStringGenerator().generate());
        identityZone.setName("The Twiglet Zone");
        identityZone.setDescription("Like the Twilight Zone but tastier.");
        return identityZone;
    }

    @Test
    public void testCreateInvalidZone() throws Exception {
        IdentityZone identityZone = new IdentityZone();
        IdentityZoneCreationRequest creationRequest = new IdentityZoneCreationRequest();
        creationRequest.setIdentityZone(identityZone);
        mockMvc.perform(post("/identity-zones")
                        .header("Authorization", "Bearer "+identityAdminToken)
                        .contentType(APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(creationRequest)))
                        .andExpect(status().isBadRequest());
    }
    
    // update a zone with a subdomain that already exists
    // update a zone in place  with different data (happy)
    // update a zone with exactly the same data (happy)

    @Test
    public void testCreatesZonesWithDuplicateSubdomains() throws Exception {
        String subdomain = UUID.randomUUID().toString();
        String id1 = UUID.randomUUID().toString();
        String id2 = UUID.randomUUID().toString();
        IdentityZone identityZone1 = MultitenancyFixture.identityZone(id1, subdomain);
        IdentityZone identityZone2 = MultitenancyFixture.identityZone(id2, subdomain);
        IdentityZoneCreationRequest creationRequest = new IdentityZoneCreationRequest();
        creationRequest.setIdentityZone(identityZone1);
        mockMvc.perform(post("/identity-zones")
                        .header("Authorization", "Bearer "+identityAdminToken)
                        .contentType(APPLICATION_JSON)
                        .accept(APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(creationRequest)))
                        .andExpect(status().isCreated());
        
        creationRequest.setIdentityZone(identityZone2);
        mockMvc.perform(post("/identity-zones")
                        .header("Authorization", "Bearer "+identityAdminToken)
                        .contentType(APPLICATION_JSON)
                        .accept(APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(creationRequest)))
                        .andExpect(status().isConflict());
    }
    
    @Test
    public void testCreateZoneAndClients() throws Exception {
        final String id = UUID.randomUUID().toString();
        IdentityZone identityZone = getIdentityZone(id);
        identityZone.setId(id);
        IdentityZoneCreationRequest creationRequest = new IdentityZoneCreationRequest();
        creationRequest.setIdentityZone(identityZone);
        List<BaseClientDetails> clientDetails = new ArrayList<BaseClientDetails>();
        BaseClientDetails client1 = new BaseClientDetails("client1", null,null, "client_credentials", "clients.admin,scim.read,scim.write");
        client1.setClientSecret("client1Secret");
        clientDetails.add(client1);
        BaseClientDetails client2 = new BaseClientDetails("client2", null,null, "client_credentials", "clients.admin,scim.read,scim.write");
        client2.setClientSecret("client2Secret");
        clientDetails.add(client2);
        creationRequest.setClientDetails(clientDetails);
        
        mockMvc.perform(post("/identity-zones")
                        .header("Authorization", "Bearer "+identityAdminToken)
                        .contentType(APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(creationRequest)))
                        .andExpect(status().isCreated());
        mockMvc.perform(get("/oauth/token?grant_type=client_credentials")
                .header("Authorization", getBasicAuthHeaderValue(client1.getClientId(), client1.getClientSecret()))
                .with(new RequestPostProcessor() {
                    @Override
                    public MockHttpServletRequest postProcessRequest(
                            MockHttpServletRequest request) {
                        request.setServerName(id+".localhost");
                        return request;
                    }
                }))
                .andExpect(status().isOk())
                .andReturn();

        mockMvc.perform(get("/oauth/token?grant_type=client_credentials")
                .header("Authorization", getBasicAuthHeaderValue(client2.getClientId(), client2.getClientSecret()))
                .with(new RequestPostProcessor() {
                    @Override
                    public MockHttpServletRequest postProcessRequest(
                            MockHttpServletRequest request) {
                    request.setServerName(id+".localhost");
                        return request;
                    }
                }))
                .andExpect(status().isOk())
                .andReturn();
        
    }
    
    private String getBasicAuthHeaderValue(String clientId, String clientSecret) {
        final String plainCreds = clientId+":"+clientSecret;
        final byte[] plainCredsBytes = plainCreds.getBytes();
        final byte[] base64CredsBytes = Base64.encodeBase64(plainCredsBytes);
        final String base64Creds = new String(base64CredsBytes);
        return "Basic "+base64Creds;
    }
    
}
