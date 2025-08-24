package org.cloudfoundry.identity.uaa.mock.zones;

import com.fasterxml.jackson.databind.JsonNode;
import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.util.AlphanumericRandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.context.WebApplicationContext;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@DefaultTestContext
class ZonesWriteScopeMockMvcTest {
    private AlphanumericRandomValueStringGenerator generator = new AlphanumericRandomValueStringGenerator();
    private String subdomain;
    private UaaClientDetails adminClient;
    private String zoneAdminToken;
    private IdentityZone zone;

    private WebApplicationContext webApplicationContext;
    private MockMvc mockMvc;
    private TestClient testClient;

    @BeforeEach
    void setUp(
            @Autowired WebApplicationContext webApplicationContext,
            @Autowired TestClient testClient,
            @Autowired MockMvc mockMvc) throws Exception {
        this.webApplicationContext = webApplicationContext;
        this.mockMvc = mockMvc;
        this.testClient = testClient;

        subdomain = generator.generate().toLowerCase();

        adminClient = new UaaClientDetails("admin", null, "uaa.admin,scim.write,zones.write", "client_credentials,password", "uaa.admin,scim.write,zones.write");
        adminClient.setClientSecret("admin-secret");

        zone = createZoneWithClient(subdomain);

        zoneAdminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "admin-secret", "", subdomain);
    }

    @Test
    void getZoneByIdWithZonesWriteScope() throws Exception {
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
        assertThat(responseNode.get("id").asText()).isEqualTo(zone.getId());

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
    void getZonesWithZonesWriteScope() throws Exception {
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
        assertThat(responseNode.get(0).get("id").asText()).isEqualTo(zone.getId());
        assertThat(responseNode.get(1)).isNull();
    }

    @Test
    void putZonesWithZonesWriteScope() throws Exception {
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
    void postZonesWithZonesWriteScopeShouldFail() throws Exception {
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
    void deleteZonesWithZonesWriteScopeShouldFail() throws Exception {
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
        MockMvcUtils.IdentityZoneCreationResult izCreationResult = MockMvcUtils.createOtherIdentityZoneAndReturnResult(subdomain, mockMvc, webApplicationContext, adminClient, IdentityZoneHolder.getCurrentZoneId());
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
