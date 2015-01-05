package org.cloudfoundry.identity.uaa.mock.zones;


import static org.junit.Assert.assertNotEquals;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import org.apache.commons.codec.binary.Base64;
import org.cloudfoundry.identity.uaa.authentication.Origin;
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
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
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

    @Test
    public void testCreateZone() throws Exception {
    	String id = UUID.randomUUID().toString();
        IdentityZone identityZone = getIdentityZone(id);
        IdentityZoneCreationRequest creationRequest = new IdentityZoneCreationRequest();
        creationRequest.setIdentityZone(identityZone);
        
        mockMvc.perform(put("/identity-zones/" + id)
                        .header("Authorization", "Bearer "+identityAdminToken)
                        .contentType(APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(creationRequest)))
                        .andExpect(status().isCreated())
                        .andExpect(content().string(""))
                        .andReturn();
    }

    @Test
    public void testCreateZoneAndIdentityProvider() throws Exception {
    	IdentityZoneCreationRequest creationRequest = new IdentityZoneCreationRequest();
    	String id = UUID.randomUUID().toString();
        IdentityZone identityZone = getIdentityZone(id);
        // this needs to be set because we're setting the IdentityZoneHolder with this identityZone
        // and code that uses the IdentityZoneHolder expects there to be an id in the zone
        identityZone.setId(id);
        creationRequest.setIdentityZone(identityZone);
        
        mockMvc.perform(put("/identity-zones/" + id)
                        .header("Authorization", "Bearer "+identityAdminToken)
                        .contentType(APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(creationRequest)))
                        .andExpect(status().isCreated())
                        .andExpect(content().string(""))
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
        identityZone.setSubdomain(subdomain);
        identityZone.setName("The Twiglet Zone");
        identityZone.setDescription("Like the Twilight Zone but tastier.");
        return identityZone;
    }

    @Test
    public void testCreateInvalidZone() throws Exception {
        IdentityZone identityZone = new IdentityZone();
        String id = UUID.randomUUID().toString();
        IdentityZoneCreationRequest creationRequest = new IdentityZoneCreationRequest();
        creationRequest.setIdentityZone(identityZone);
        mockMvc.perform(put("/identity-zones/" + id)
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
        mockMvc.perform(put("/identity-zones/" + UUID.randomUUID().toString())
                        .header("Authorization", "Bearer "+identityAdminToken)
                        .contentType(APPLICATION_JSON)
                        .accept(APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(creationRequest)))
                        .andExpect(status().isCreated());
        
        creationRequest.setIdentityZone(identityZone2);
        mockMvc.perform(put("/identity-zones/" + UUID.randomUUID().toString())
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
        
        mockMvc.perform(put("/identity-zones/" + id)
                        .header("Authorization", "Bearer "+identityAdminToken)
                        .contentType(APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(creationRequest)))
                        .andExpect(status().isCreated())
                        .andExpect(content().string(""))
                        .andReturn();
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
