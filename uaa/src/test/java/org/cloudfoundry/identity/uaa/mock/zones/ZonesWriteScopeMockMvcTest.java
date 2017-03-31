package org.cloudfoundry.identity.uaa.mock.zones;

import com.fasterxml.jackson.databind.JsonNode;
import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.test.web.servlet.MvcResult;

import java.util.Arrays;
import java.util.Collections;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class ZonesWriteScopeMockMvcTest  extends InjectedMockContextTest {
    private RandomValueStringGenerator generator = new RandomValueStringGenerator();
    protected final InjectedMockContextTest.TestClient testClient = new InjectedMockContextTest.TestClient();
    String subdomain;
    BaseClientDetails adminClient;
    String zoneAdminToken;
    IdentityZone zone;

    @Before
    public void setUp() throws Exception {
        subdomain = generator.generate().toLowerCase();

        adminClient = new BaseClientDetails("admin", null, "uaa.admin,scim.write,zones.write", "client_credentials,password", "uaa.admin,scim.write,zones.write");
        adminClient.setClientSecret("admin-secret");

        zone = createZoneWithClient(subdomain);

        zoneAdminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "admin-secret", "", subdomain);
    }

    @Test
    public void testGetZoneByIdWithZonesWriteScope() throws Exception {

        createUserWithZonesWriteScope(zoneAdminToken);

        String zonesWriteToken = testClient.getUserOAuthAccessTokenForZone("admin", "admin-secret", "marissa", "koala", "zones.write", subdomain);

        MvcResult result = getMockMvc().perform(
            get("/identity-zones/" + zone.getId())
                .header("Authorization", "Bearer " + zonesWriteToken)
                .header("Host", subdomain + ".localhost")
                .accept(APPLICATION_JSON))
            .andExpect(status().isOk())
            .andReturn();

        String jsonResponse = result.getResponse().getContentAsString();
        JsonNode responseNode = JsonUtils.readTree(jsonResponse);
        assertEquals(zone.getId() ,responseNode.get("id").asText());
    }

    @Test
    public void testGetZonesWithZonesWriteScope() throws Exception {
        createZoneWithClient(generator.generate().toLowerCase());

        createUserWithZonesWriteScope(zoneAdminToken);

        String zonesWriteToken = testClient.getUserOAuthAccessTokenForZone("admin", "admin-secret", "marissa", "koala", "zones.write", subdomain);

        MvcResult result = getMockMvc().perform(
            get("/identity-zones")
                .header("Authorization", "Bearer " + zonesWriteToken)
                .header("Host", subdomain + ".localhost")
                .accept(APPLICATION_JSON))
            .andExpect(status().isOk())
            .andReturn();

        String jsonResponse = result.getResponse().getContentAsString();
        JsonNode responseNode = JsonUtils.readTree(jsonResponse);
        assertEquals(zone.getId() ,responseNode.get(0).get("id").asText());
        assertNull(responseNode.get(1));
    }

    private IdentityZone createZoneWithClient(String subdomain) throws Exception {
        MockMvcUtils.IdentityZoneCreationResult izCreationResult = MockMvcUtils.createOtherIdentityZoneAndReturnResult(subdomain, getMockMvc(), getWebApplicationContext(), adminClient);
        return izCreationResult.getIdentityZone();
    }

    private void createUserWithZonesWriteScope(String zoneAdminToken) throws Exception{
        String username = "marissa";
        String password = "koala";
        ScimUser user = new ScimUser(null, username, "Marissa", "Koala");
        user.setPrimaryEmail("marissa@test.org");
        user.setPassword(password);
        user = MockMvcUtils.createUserInZone(getMockMvc(), zoneAdminToken, user, subdomain);

        ScimGroup group = new ScimGroup(null, "zones.write", subdomain);
        group.setZoneId(zone.getId());
        group.setMembers(Collections.singletonList(new ScimGroupMember(user.getId(), ScimGroupMember.Type.USER, Arrays.asList(ScimGroupMember.Role.MEMBER))));
        MockMvcUtils.createGroup(getMockMvc(), zoneAdminToken, subdomain, group);
    }

    /*
    @Test
    public void testGetZonesByIdWithZonesWrite() throws Exception {
        String id = generator.generate();
        createZone(id, HttpStatus.CREATED, identityClientZonesWriteToken);
        createZone("forbidden", HttpStatus.CREATED, identityClientZonesWriteToken);

        getMockMvc().perform(
            get("/identity-zones/" + id)
                .header("Authorization", "Bearer " + identityClientZonesWriteToken))
            .andExpect(status().isOk());

        getMockMvc().perform(
            get("/identity-zones/forbidden")
                .header("Authorization", "Bearer " + identityClientZonesWriteToken))
            .andExpect(status().isForbidden());
    }

    @Test
    public void testUpdateZoneWithZonesWrite() throws Exception {
        String id = generator.generate();
        IdentityZone zone = createZone(id, HttpStatus.CREATED, identityClientZonesWriteToken);
        updateZone(zone, HttpStatus.OK, identityClientZonesWriteToken);
    }
*/
}
