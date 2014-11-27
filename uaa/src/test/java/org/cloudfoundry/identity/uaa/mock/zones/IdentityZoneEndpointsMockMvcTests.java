package org.cloudfoundry.identity.uaa.mock.zones;


import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.test.YamlServletProfileInitializerContextInitializer;
import org.cloudfoundry.identity.uaa.zone.IdentityProvider;
import org.cloudfoundry.identity.uaa.zone.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.codehaus.jackson.map.ObjectMapper;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.support.XmlWebApplicationContext;

import java.util.UUID;

import static org.junit.Assert.*;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

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

    @Test
    public void testCreateZone() throws Exception {
        IdentityZone identityZone = getIdentityZone("mysubdomain1");
        String id = UUID.randomUUID().toString();
        
        mockMvc.perform(put("/identity-zones/" + id)
                        .header("Authorization", "Bearer "+identityAdminToken)
                        .contentType(APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(identityZone)))
                        .andExpect(status().isCreated())
                        .andExpect(content().string(""))
                        .andReturn();
    }

    @Test
    public void testCreateZoneAndIdentityZone() throws Exception {
        IdentityZone identityZone = getIdentityZone("mysubdomain2");
        String id = UUID.randomUUID().toString();
        identityZone.setId(id);
        
        mockMvc.perform(put("/identity-zones/" + id)
                        .header("Authorization", "Bearer "+identityAdminToken)
                        .contentType(APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(identityZone)))
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

        mockMvc.perform(put("/identity-zones/" + id)
                        .header("Authorization", "Bearer "+identityAdminToken)
                        .contentType(APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(identityZone)))
                        .andExpect(status().isBadRequest());
    }
    
    // update a zone with a subdomain that already exists
    // update a zone in place  with different data (happy)
    // update a zone with exactly the same data (happy)

    @Test
    public void testCreatesZonesWithDuplicateSubdomains() throws Exception {
        IdentityZone identityZone = new IdentityZone();
        identityZone.setSubdomain("other-subdomain");
        identityZone.setName("The Twiglet Zone 2");

        mockMvc.perform(put("/identity-zones/" + UUID.randomUUID().toString())
                        .header("Authorization", "Bearer "+identityAdminToken)
                        .contentType(APPLICATION_JSON)
                        .accept(APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(identityZone)))
                        .andExpect(status().isCreated());

        mockMvc.perform(put("/identity-zones/" + UUID.randomUUID().toString())
                        .header("Authorization", "Bearer "+identityAdminToken)
                        .contentType(APPLICATION_JSON)
                        .accept(APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(identityZone)))
                        .andExpect(status().isConflict());
    }
    
}
