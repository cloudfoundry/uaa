package org.cloudfoundry.identity.uaa.mock.zones;

import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.SetServerNameRequestPostProcessor;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultMatcher;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import java.util.Collections;
import java.util.UUID;

import static org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter.HEADER;
import static org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter.SUBDOMAIN_HEADER;
import static org.junit.Assert.assertEquals;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class IdentityZoneSwitchingFilterMockMvcTest extends InjectedMockContextTest {

    private String identityToken;
    private String adminToken;
    private RandomValueStringGenerator generator;

    @Before
    public void setUp() throws Exception {
        identityToken = testClient.getClientCredentialsOAuthAccessToken(
                "identity",
                "identitysecret",
                "zones.write,scim.zones");

        adminToken = testClient.getClientCredentialsOAuthAccessToken(
                "admin",
                "adminsecret",
                "");

        generator = new RandomValueStringGenerator();
    }

    @Test
    public void testSwitchingZones() throws Exception {
        IdentityZone identityZone = createZone(getMockMvc(), identityToken);
        String zoneId = identityZone.getId();
        String zoneAdminToken = MockMvcUtils.getZoneAdminToken(getMockMvc(), adminToken, zoneId);
        // Using Identity Client, authenticate in originating Zone
        // - Create Client using X-Identity-Zone-Id header in new Zone
        ClientDetails client = createClientInOtherZone(getMockMvc(), generator, zoneAdminToken, status().isCreated(), HEADER, zoneId);

        // Authenticate with new Client in new Zone
        getMockMvc().perform(post("/oauth/token")
                .param("grant_type", "client_credentials")
                .with(httpBasic(client.getClientId(), client.getClientSecret()))
                .with(new SetServerNameRequestPostProcessor(identityZone.getSubdomain() + ".localhost")))
                .andExpect(status().isOk());
    }

    @Test
    public void testSwitchingZoneWithSubdomain() throws Exception {
        IdentityZone identityZone = createZone(getMockMvc(), identityToken);
        String zoneAdminToken = MockMvcUtils.getZoneAdminToken(getMockMvc(), adminToken, identityZone.getId());
        ClientDetails client = createClientInOtherZone(getMockMvc(), generator, zoneAdminToken, status().isCreated(), SUBDOMAIN_HEADER, identityZone.getSubdomain());

        getMockMvc().perform(
                post("/oauth/token")
                        .param("grant_type", "client_credentials")
                        .with(httpBasic(client.getClientId(), client.getClientSecret()))
                        .with(new SetServerNameRequestPostProcessor(identityZone.getSubdomain() + ".localhost")))
                .andExpect(status().isOk());
    }

    @Test
    public void testNoSwitching() throws Exception {
        final String clientId = UUID.randomUUID().toString();
        BaseClientDetails client = new BaseClientDetails(clientId, null, null, "client_credentials", null);
        client.setClientSecret("secret");

        getMockMvc().perform(post("/oauth/clients")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(client)))
                .andExpect(status().isCreated());

        getMockMvc().perform(
                post("/oauth/token")
                        .param("grant_type", "client_credentials")
                        .with(httpBasic(client.getClientId(), client.getClientSecret())))
                .andExpect(status().isOk());
    }

    @Test
    public void testSwitchingToInvalidSubDomain() throws Exception {
        IdentityZone identityZone = createZone(getMockMvc(), identityToken);
        String zoneAdminToken = MockMvcUtils.getZoneAdminToken(getMockMvc(), adminToken, identityZone.getId());

        createClientInOtherZone(getMockMvc(), generator, zoneAdminToken, status().isNotFound(), SUBDOMAIN_HEADER, "InvalidSubDomain");
    }

    @Test
    public void testSwitchingToNonExistentZone() throws Exception {
        IdentityZone identityZone = createZone(getMockMvc(), identityToken);
        String zoneAdminToken = MockMvcUtils.getZoneAdminToken(getMockMvc(), adminToken, identityZone.getId());

        createClientInOtherZone(getMockMvc(), generator, zoneAdminToken, status().isNotFound(), HEADER, "i-do-not-exist");
    }

    @Test
    public void testSwitchingZonesWithoutAuthority() throws Exception {
        String identityTokenWithoutZonesAdmin = testClient.getClientCredentialsOAuthAccessToken("identity", "identitysecret", "zones.write,scim.zones");
        final String zoneId = createZone(getMockMvc(), identityTokenWithoutZonesAdmin).getId();
        createClientInOtherZone(getMockMvc(), generator, identityTokenWithoutZonesAdmin, status().isForbidden(), HEADER, zoneId);
    }

    @Test
    public void testSwitchingZonesWithAUser() throws Exception {
        final String zoneId = createZone(getMockMvc(), identityToken).getId();
        String adminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret", "scim.write");
        // Create a User
        String username = generator.generate() + "@example.com";
        ScimUser user = getScimUser(username);
        ScimUser createdUser = MockMvcUtils.createUser(getMockMvc(), adminToken, user);
        ScimGroup group = new ScimGroup(null, "zones." + zoneId + ".admin", zoneId);
        group.setMembers(Collections.singletonList(new ScimGroupMember(createdUser.getId())));
        MockMvcUtils.createGroup(getMockMvc(), adminToken, group);
        String userToken = MockMvcUtils.getUserOAuthAccessTokenAuthCode(getMockMvc(), "identity", "identitysecret", createdUser.getId(), createdUser.getUserName(), "secret", null);
        createClientInOtherZone(getMockMvc(), generator, userToken, status().isCreated(), HEADER, zoneId);
    }

    @Test
    public void test_scim_read_in_another_zone() throws Exception {
        final String zoneId = createZone(getMockMvc(), identityToken).getId();
        ScimUser user = createScimUserUsingZonesScimWrite(getMockMvc(), generator, testClient, zoneId);
        String adminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret", "scim.write");
        String scimReadZoneToken = MockMvcUtils.getZoneAdminToken(getMockMvc(), adminToken, zoneId, "zones." + zoneId + ".scim.read");
        ScimUser readUser = MockMvcUtils.readUserInZone(getMockMvc(), scimReadZoneToken, user.getId(), "", zoneId);
        assertEquals(user.getId(), readUser.getId());
    }

    @Test
    public void test_scim_create_in_another_zone() throws Exception {
        final String zoneId = createZone(getMockMvc(), identityToken).getId();
        String adminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret", "scim.write");
        String scimCreateZoneToken = MockMvcUtils.getZoneAdminToken(getMockMvc(), adminToken, zoneId, "zones." + zoneId + ".scim.create");
        createUserInAnotherZone(getMockMvc(), generator, scimCreateZoneToken, zoneId);
    }

    @Test
    public void test_scim_write_in_another_zone() throws Exception {
        final String zoneId = createZone(getMockMvc(), identityToken).getId();
        createScimUserUsingZonesScimWrite(getMockMvc(), generator, testClient, zoneId);
    }

    private static ScimUser getScimUser(String username) {
        ScimUser user = new ScimUser();
        user.setUserName(username);
        user.addEmail(username);
        user.setPassword("secr3T");
        user.setVerified(true);
        user.setZoneId(IdentityZone.getUaa().getId());
        return user;
    }

    private static ScimUser createScimUserUsingZonesScimWrite(MockMvc mockMvc, RandomValueStringGenerator generator, TestClient testClient, String zoneId) throws Exception {
        String adminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret", "scim.write");
        String scimWriteZoneToken = MockMvcUtils.getZoneAdminToken(mockMvc, adminToken, zoneId, "zones." + zoneId + ".scim.write");
        return createUserInAnotherZone(mockMvc, generator, scimWriteZoneToken, zoneId);
    }

    private static IdentityZone createZone(MockMvc mockMvc, String accessToken) throws Exception {
        return MockMvcUtils.createZoneUsingWebRequest(mockMvc, accessToken);
    }

    private static ScimUser createUserInAnotherZone(MockMvc mockMvc, RandomValueStringGenerator generator, String accessToken, String zoneId) throws Exception {
        String username = generator.generate() + "@example.com";
        ScimUser user = getScimUser(username);
        return MockMvcUtils.createUserInZone(mockMvc, accessToken, user, "", zoneId);
    }

    private static ClientDetails createClientInOtherZone(MockMvc mockMvc, RandomValueStringGenerator generator, String accessToken, ResultMatcher statusMatcher, String headerKey, String headerValue) throws Exception {
        String clientId = generator.generate();
        BaseClientDetails client = new BaseClientDetails(clientId, null, null, "client_credentials", null);
        client.setClientSecret("secret");
        mockMvc.perform(post("/oauth/clients")
                .header(headerKey, headerValue)
                .with(httpBearer(accessToken))
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(client)))
                .andExpect(statusMatcher);
        return client;
    }

    private static RequestPostProcessor httpBearer(String authorization) {
        return new HttpBearerAuthRequestPostProcessor(authorization);
    }

    private static class HttpBearerAuthRequestPostProcessor implements RequestPostProcessor {
        private String headerValue;

        private HttpBearerAuthRequestPostProcessor(String authorization) {
            this.headerValue = "Bearer " + authorization;
        }

        @Override
        public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
            request.addHeader("Authorization", this.headerValue);
            return request;
        }
    }
}
