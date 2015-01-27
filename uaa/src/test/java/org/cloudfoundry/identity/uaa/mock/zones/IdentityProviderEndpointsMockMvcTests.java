package org.cloudfoundry.identity.uaa.mock.zones;

import com.googlecode.flyway.core.Flyway;
import org.apache.commons.lang.RandomStringUtils;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.test.YamlServletProfileInitializerContextInitializer;
import org.cloudfoundry.identity.uaa.zone.IdentityProvider;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.codehaus.jackson.map.ObjectMapper;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultMatcher;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.support.XmlWebApplicationContext;

import java.util.Arrays;

import static java.util.Arrays.asList;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class IdentityProviderEndpointsMockMvcTests {
    private static XmlWebApplicationContext webApplicationContext;
    private static MockMvc mockMvc;
    private static TestClient testClient = null;
    private static String adminToken;
    private static String identityToken;
    private static MockMvcUtils mockMvcUtils;

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

        adminToken = testClient.getClientCredentialsOAuthAccessToken(
            "admin",
            "adminsecret",
            "");
        identityToken = testClient.getClientCredentialsOAuthAccessToken(
            "identity",
            "identitysecret",
            "zones.create");
        mockMvcUtils = MockMvcUtils.utils();
    }

    @AfterClass
    public static void tearDown() throws Exception {
        Flyway flyway = webApplicationContext.getBean(Flyway.class);
        flyway.clean();
        webApplicationContext.close();
    }

    @Test
    public void testCreateIdentityProvider() throws Exception {
        BaseClientDetails client = new BaseClientDetails("test-client-id",null,"idps.write","password",null);
        client.setClientSecret("test-client-secret");
        mockMvcUtils.createClient(mockMvc, adminToken, client);

        ScimUser user = createAdminForZone("idps.write");
        String accessToken = mockMvcUtils.getUserOAuthAccessToken(mockMvc, client.getClientId(), client.getClientSecret(), user.getUserName(), "password", "idps.write");

        IdentityProvider identityProvider = MultitenancyFixture.identityProvider("saml");
        MvcResult result = createIdentityProvider(null, identityProvider, accessToken, status().isCreated());
        IdentityProvider createdIDP = new ObjectMapper().readValue(result.getResponse().getContentAsString(), IdentityProvider.class);
        assertNotNull(createdIDP.getId());
        assertEquals(identityProvider.getName(), createdIDP.getName());
        assertEquals(identityProvider.getOriginKey(), createdIDP.getOriginKey());
    }

    @Test
    public void testCreateIdentityProviderWithInsufficientScopes() throws Exception {
        IdentityProvider identityProvider = MultitenancyFixture.identityProvider("saml");
        createIdentityProvider(null, identityProvider, adminToken, status().isForbidden());
    }

    @Test
    public void testCreateIdentityProviderInOtherZone() throws Exception {
        IdentityProvider identityProvider = MultitenancyFixture.identityProvider("saml");
        IdentityZone zone = mockMvcUtils.createZoneUsingWebRequest(mockMvc,identityToken);
        ScimUser user = createAdminForZone("zones." + zone.getId() + ".admin");

        String userAccessToken = testClient.getUserOAuthAccessToken("identity", "identitysecret", user.getUserName(), "password", "zones." + zone.getId() + ".admin");

        MvcResult result = createIdentityProvider(zone.getId(), identityProvider, userAccessToken, status().isCreated());
        IdentityProvider createdIDP = new ObjectMapper().readValue(result.getResponse().getContentAsString(), IdentityProvider.class);
        assertNotNull(createdIDP.getId());
        assertEquals(identityProvider.getName(), createdIDP.getName());
        assertEquals(identityProvider.getOriginKey(), createdIDP.getOriginKey());

    }

    private MvcResult createIdentityProvider(String zoneId, IdentityProvider identityProvider, String token, ResultMatcher resultMatcher) throws Exception {
        MockHttpServletRequestBuilder requestBuilder = post("/identity-providers/")
            .header("Authorization", "Bearer" + token)
            .contentType(APPLICATION_JSON)
            .content(new ObjectMapper().writeValueAsString(identityProvider));
        if (zoneId != null) {
            requestBuilder.header(IdentityZoneSwitchingFilter.HEADER, zoneId);
        }
        return mockMvc.perform(requestBuilder)
                .andExpect(resultMatcher)
                .andReturn();
    }

    private ScimUser createAdminForZone(String scope) throws Exception {
        String random = RandomStringUtils.randomAlphabetic(6);
        ScimUser user = new ScimUser();
        user.setUserName(random + "@example.com");
        ScimUser.Email email = new ScimUser.Email();
        email.setValue(random + "@example.com");
        user.setEmails(asList(email));
        user.setPassword("password");
        ScimUser createdUser = mockMvcUtils.createUser(mockMvc, adminToken, user);


        // Create the zones.<zone_id>.admin Group
        // Add User to the zones.<zone_id>.admin Group
        ScimGroup group = new ScimGroup(scope);
        group.setMembers(Arrays.asList(new ScimGroupMember(createdUser.getId())));
        mockMvcUtils.createGroup(mockMvc,adminToken,group);
        return createdUser;
    }
}
