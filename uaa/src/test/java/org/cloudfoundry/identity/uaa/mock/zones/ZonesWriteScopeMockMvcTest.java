package org.cloudfoundry.identity.uaa.mock.zones;

import com.fasterxml.jackson.databind.JsonNode;
import org.cloudfoundry.identity.uaa.SpringServletAndHoneycombTestConfig;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.HoneycombAuditEventListenerRule;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.util.Collections;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringJUnit4ClassRunner.class)
@ActiveProfiles("default")
@WebAppConfiguration
@ContextConfiguration(classes = SpringServletAndHoneycombTestConfig.class)
public class ZonesWriteScopeMockMvcTest {
    @Rule
    public HoneycombAuditEventListenerRule honeycombAuditEventListenerRule = new HoneycombAuditEventListenerRule();

    private RandomValueStringGenerator generator = new RandomValueStringGenerator();
    protected TestClient testClient;
    private String subdomain;
    private BaseClientDetails adminClient;
    private String zoneAdminToken;
    private IdentityZone zone;
    @Autowired
    public WebApplicationContext webApplicationContext;
    private MockMvc mockMvc;

    @Before
    public void setUp() throws Exception {
        FilterChainProxy springSecurityFilterChain = webApplicationContext.getBean("springSecurityFilterChain", FilterChainProxy.class);
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
                .addFilter(springSecurityFilterChain)
                .build();

        testClient = new TestClient(mockMvc);
        subdomain = generator.generate().toLowerCase();

        adminClient = new BaseClientDetails("admin", null, "uaa.admin,scim.write,zones.write", "client_credentials,password", "uaa.admin,scim.write,zones.write");
        adminClient.setClientSecret("admin-secret");

        zone = createZoneWithClient(subdomain);

        zoneAdminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "admin-secret", "", subdomain);
    }

    @Test
    public void testGetZoneByIdWithZonesWriteScope() throws Exception {
        IdentityZone zone2 = createZoneWithClient(generator.generate().toLowerCase());
        createUserWithZonesWriteScope(zoneAdminToken);

        String zonesWriteToken = testClient.getUserOAuthAccessTokenForZone("admin", "admin-secret", "marissa", "koala", "zones.write", subdomain);

        MvcResult result = mockMvc.perform(
                get("/identity-zones/" + zone.getId())
                        .header("Authorization", "Bearer " + zonesWriteToken)
                        .header("Host", subdomain + ".localhost")
                        .accept(APPLICATION_JSON))
                .andExpect(status().isOk())
                .andReturn();

        String jsonResponse = result.getResponse().getContentAsString();
        JsonNode responseNode = JsonUtils.readTree(jsonResponse);
        assertEquals(zone.getId(), responseNode.get("id").asText());

        mockMvc.perform(
                get("/identity-zones/" + zone2.getId())
                        .header("Authorization", "Bearer " + zonesWriteToken)
                        .header("Host", subdomain + ".localhost")
                        .accept(APPLICATION_JSON))
                .andExpect(status().isNotFound());

        mockMvc.perform(
                get("/identity-zones/uaa")
                        .header("Authorization", "Bearer " + zonesWriteToken)
                        .accept(APPLICATION_JSON))
                .andExpect(status().isUnauthorized());
    }

    @Test
    public void testGetZonesWithZonesWriteScope() throws Exception {
        createZoneWithClient(generator.generate().toLowerCase());

        createUserWithZonesWriteScope(zoneAdminToken);

        String zonesWriteToken = testClient.getUserOAuthAccessTokenForZone("admin", "admin-secret", "marissa", "koala", "zones.write", subdomain);

        MvcResult result = mockMvc.perform(
                get("/identity-zones")
                        .header("Authorization", "Bearer " + zonesWriteToken)
                        .header("Host", subdomain + ".localhost")
                        .accept(APPLICATION_JSON))
                .andExpect(status().isOk())
                .andReturn();

        String jsonResponse = result.getResponse().getContentAsString();
        JsonNode responseNode = JsonUtils.readTree(jsonResponse);
        assertEquals(zone.getId(), responseNode.get(0).get("id").asText());
        assertNull(responseNode.get(1));
    }

    @Test
    public void testPutZonesWithZonesWriteScope() throws Exception {
        createZoneWithClient(generator.generate().toLowerCase());

        createUserWithZonesWriteScope(zoneAdminToken);

        String zonesWriteToken = testClient.getUserOAuthAccessTokenForZone("admin", "admin-secret", "marissa", "koala", "zones.write", subdomain);

        mockMvc.perform(
                put("/identity-zones/" + zone.getId())
                        .header("Authorization", "Bearer " + zonesWriteToken)
                        .header("Host", subdomain + ".localhost")
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(zone)))
                .andExpect(status().isOk())
                .andReturn();

        mockMvc.perform(
                put("/identity-zones/uaa")
                        .header("Authorization", "Bearer " + zonesWriteToken)
                        .header("Host", subdomain + ".localhost")
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(zone)))
                .andExpect(status().isForbidden())
                .andReturn();
    }

    @Test
    public void testPostZonesWithZonesWriteScope_shouldFail() throws Exception {
        IdentityZone zone2 = MultitenancyFixture.identityZone(subdomain, subdomain);

        createUserWithZonesWriteScope(zoneAdminToken);

        String zonesWriteToken = testClient.getUserOAuthAccessTokenForZone("admin", "admin-secret", "marissa", "koala", "zones.write", subdomain);

        mockMvc.perform(
                post("/identity-zones")
                        .header("Authorization", "Bearer " + zonesWriteToken)
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(zone2)))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(
                post("/identity-zones")
                        .header("Authorization", "Bearer " + zonesWriteToken)
                        .header("Host", subdomain + ".localhost")
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(zone2)))
                .andExpect(status().isForbidden());
    }

    @Test
    public void testDeleteZonesWithZonesWriteScope_shouldFail() throws Exception {
        IdentityZone zone2 = createZoneWithClient(generator.generate().toLowerCase());

        createUserWithZonesWriteScope(zoneAdminToken);

        String zonesWriteToken = testClient.getUserOAuthAccessTokenForZone("admin", "admin-secret", "marissa", "koala", "zones.write", subdomain);

        mockMvc.perform(
                delete("/identity-zones/" + zone2.getId())
                        .header("Authorization", "Bearer " + zonesWriteToken)
                        .contentType(APPLICATION_JSON))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(
                delete("/identity-zones/" + zone2.getId())
                        .header("Authorization", "Bearer " + zonesWriteToken)
                        .header("Host", zone2.getSubdomain() + ".localhost")
                        .contentType(APPLICATION_JSON))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(
                delete("/identity-zones/uaa")
                        .header("Authorization", "Bearer " + zonesWriteToken)
                        .contentType(APPLICATION_JSON))
                .andExpect(status().isUnauthorized());
    }

    private IdentityZone createZoneWithClient(String subdomain) throws Exception {
        MockMvcUtils.IdentityZoneCreationResult izCreationResult = MockMvcUtils.createOtherIdentityZoneAndReturnResult(subdomain, mockMvc, webApplicationContext, adminClient);
        return izCreationResult.getIdentityZone();
    }

    private void createUserWithZonesWriteScope(String zoneAdminToken) throws Exception {
        String username = "marissa";
        String password = "koala";
        ScimUser user = new ScimUser(null, username, "Marissa", "Koala");
        user.setPrimaryEmail("marissa@test.org");
        user.setPassword(password);
        user = MockMvcUtils.createUserInZone(mockMvc, zoneAdminToken, user, subdomain);

        ScimGroup group = new ScimGroup(null, "zones.write", subdomain);
        group.setZoneId(zone.getId());
        group.setMembers(Collections.singletonList(new ScimGroupMember(user.getId(), ScimGroupMember.Type.USER)));
        MockMvcUtils.createGroup(mockMvc, zoneAdminToken, subdomain, group);
    }
}
