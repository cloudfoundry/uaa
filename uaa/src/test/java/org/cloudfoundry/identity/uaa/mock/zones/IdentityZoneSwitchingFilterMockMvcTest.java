package org.cloudfoundry.identity.uaa.mock.zones;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.util.AlphanumericRandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.SetServerNameRequestPostProcessor;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultMatcher;

import java.util.Collections;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.httpBearer;
import static org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter.HEADER;
import static org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter.SUBDOMAIN_HEADER;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@DefaultTestContext
class IdentityZoneSwitchingFilterMockMvcTest {

    private String identityToken;
    private String adminToken;
    private AlphanumericRandomValueStringGenerator generator;

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private TestClient testClient;

    @BeforeEach
    void setUp() throws Exception {
        identityToken = testClient.getClientCredentialsOAuthAccessToken(
                "identity",
                "identitysecret",
                "zones.write,scim.zones");

        adminToken = testClient.getClientCredentialsOAuthAccessToken(
                "admin",
                "adminsecret",
                "");

        generator = new AlphanumericRandomValueStringGenerator();
    }

    @Test
    void switchingZones() throws Exception {
        IdentityZone identityZone = createZone(mockMvc, identityToken);
        String zoneId = identityZone.getId();
        String zoneAdminToken = MockMvcUtils.getZoneAdminToken(mockMvc, adminToken, zoneId);
        // Using Identity Client, authenticate in originating Zone
        // - Create Client using X-Identity-Zone-Id header in new Zone
        ClientDetails client = createClientInOtherZone(mockMvc, generator, zoneAdminToken, status().isCreated(), HEADER, zoneId);

        // Authenticate with new Client in new Zone
        mockMvc.perform(post("/oauth/token")
                        .param("grant_type", "client_credentials")
                        .with(httpBasic(client.getClientId(), client.getClientSecret()))
                        .with(new SetServerNameRequestPostProcessor(identityZone.getSubdomain() + ".localhost")))
                .andExpect(status().isOk());
    }

    @Test
    void switchingZoneWithSubdomain() throws Exception {
        IdentityZone identityZone = createZone(mockMvc, identityToken);
        String zoneAdminToken = MockMvcUtils.getZoneAdminToken(mockMvc, adminToken, identityZone.getId());
        ClientDetails client = createClientInOtherZone(mockMvc, generator, zoneAdminToken, status().isCreated(), SUBDOMAIN_HEADER, identityZone.getSubdomain());

        mockMvc.perform(
                        post("/oauth/token")
                                .param("grant_type", "client_credentials")
                                .with(httpBasic(client.getClientId(), client.getClientSecret()))
                                .with(new SetServerNameRequestPostProcessor(identityZone.getSubdomain() + ".localhost")))
                .andExpect(status().isOk());
    }

    @Test
    void noSwitching() throws Exception {
        final String clientId = UUID.randomUUID().toString();
        UaaClientDetails client = new UaaClientDetails(clientId, null, null, "client_credentials", null);
        client.setClientSecret("secret");

        mockMvc.perform(post("/oauth/clients")
                        .header("Authorization", "Bearer " + adminToken)
                        .accept(APPLICATION_JSON)
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(client)))
                .andExpect(status().isCreated());

        mockMvc.perform(
                        post("/oauth/token")
                                .param("grant_type", "client_credentials")
                                .with(httpBasic(client.getClientId(), client.getClientSecret())))
                .andExpect(status().isOk());
    }

    @Test
    void switchingToInvalidSubDomain() throws Exception {
        IdentityZone identityZone = createZone(mockMvc, identityToken);
        String zoneAdminToken = MockMvcUtils.getZoneAdminToken(mockMvc, adminToken, identityZone.getId());

        createClientInOtherZone(mockMvc, generator, zoneAdminToken, status().isNotFound(), SUBDOMAIN_HEADER, "InvalidSubDomain");
    }

    @Test
    void switchingToNonExistentZone() throws Exception {
        IdentityZone identityZone = createZone(mockMvc, identityToken);
        String zoneAdminToken = MockMvcUtils.getZoneAdminToken(mockMvc, adminToken, identityZone.getId());

        createClientInOtherZone(mockMvc, generator, zoneAdminToken, status().isNotFound(), HEADER, "i-do-not-exist");
    }

    @Test
    void switchingZonesWithoutAuthority() throws Exception {
        String identityTokenWithoutZonesAdmin = testClient.getClientCredentialsOAuthAccessToken("identity", "identitysecret", "zones.write,scim.zones");
        final String zoneId = createZone(mockMvc, identityTokenWithoutZonesAdmin).getId();
        createClientInOtherZone(mockMvc, generator, identityTokenWithoutZonesAdmin, status().isForbidden(), HEADER, zoneId);
    }

    @Test
    void switchingZonesWithAUser() throws Exception {
        final String zoneId = createZone(mockMvc, identityToken).getId();
        String adminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret", "scim.write");
        // Create a User
        String username = generator.generate() + "@example.com";
        ScimUser user = getScimUser(username);
        ScimUser createdUser = MockMvcUtils.createUser(mockMvc, adminToken, user);
        ScimGroup group = new ScimGroup(null, "zones." + zoneId + ".admin", zoneId);
        group.setMembers(Collections.singletonList(new ScimGroupMember(createdUser.getId())));
        MockMvcUtils.createGroup(mockMvc, adminToken, group);
        String userToken = MockMvcUtils.getUserOAuthAccessTokenAuthCode(mockMvc, "identity", "identitysecret", createdUser.getId(), createdUser.getUserName(), "secret", null);
        createClientInOtherZone(mockMvc, generator, userToken, status().isCreated(), HEADER, zoneId);
    }

    @Test
    void scimReadInAnotherZone() throws Exception {
        final String zoneId = createZone(mockMvc, identityToken).getId();
        ScimUser user = createScimUserUsingZonesScimWrite(mockMvc, generator, testClient, zoneId);
        String adminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret", "scim.write");
        String scimReadZoneToken = MockMvcUtils.getZoneAdminToken(mockMvc, adminToken, zoneId, "zones." + zoneId + ".scim.read");
        ScimUser readUser = MockMvcUtils.readUserInZone(mockMvc, scimReadZoneToken, user.getId(), "", zoneId);
        assertThat(readUser.getId()).isEqualTo(user.getId());
    }

    @Test
    void scimCreateInAnotherZone() throws Exception {
        final String zoneId = createZone(mockMvc, identityToken).getId();
        String adminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret", "scim.write");
        String scimCreateZoneToken = MockMvcUtils.getZoneAdminToken(mockMvc, adminToken, zoneId, "zones." + zoneId + ".scim.create");
        createUserInAnotherZone(mockMvc, generator, scimCreateZoneToken, zoneId);
    }

    @Test
    void scimWriteInAnotherZone() throws Exception {
        final String zoneId = createZone(mockMvc, identityToken).getId();
        createScimUserUsingZonesScimWrite(mockMvc, generator, testClient, zoneId);
    }

    @Test
    void switchToUaaZone_superfluous_switch_header() throws Exception {

        mockMvc.perform(
                        post("/oauth/token")
                                .accept(APPLICATION_JSON)
                                .contentType(APPLICATION_FORM_URLENCODED)
                                .header(HEADER, IdentityZone.getUaa().getId())
                                .param("grant_type", "password")
                                .param("client_id", "cf")
                                .param("client_secret", "")
                                .param("username", "marissa")
                                .param("password", "koala")
                )
                //previously caused a ClassCastException
                .andExpect(status().isOk());
    }

    private static ScimUser getScimUser(String username) {
        ScimUser user = new ScimUser();
        user.setUserName(username);
        user.addEmail(username);
        user.setPassword("secr3T");
        user.setVerified(true);
        user.setZoneId(IdentityZone.getUaaZoneId());
        return user;
    }

    private static ScimUser createScimUserUsingZonesScimWrite(MockMvc mockMvc, AlphanumericRandomValueStringGenerator generator, TestClient testClient, String zoneId) throws Exception {
        String adminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret", "scim.write");
        String scimWriteZoneToken = MockMvcUtils.getZoneAdminToken(mockMvc, adminToken, zoneId, "zones." + zoneId + ".scim.write");
        return createUserInAnotherZone(mockMvc, generator, scimWriteZoneToken, zoneId);
    }

    private static IdentityZone createZone(MockMvc mockMvc, String accessToken) throws Exception {
        return MockMvcUtils.createZoneUsingWebRequest(mockMvc, accessToken);
    }

    private static ScimUser createUserInAnotherZone(MockMvc mockMvc, AlphanumericRandomValueStringGenerator generator, String accessToken, String zoneId) throws Exception {
        String username = generator.generate() + "@example.com";
        ScimUser user = getScimUser(username);
        return MockMvcUtils.createUserInZone(mockMvc, accessToken, user, "", zoneId);
    }

    private static ClientDetails createClientInOtherZone(MockMvc mockMvc, AlphanumericRandomValueStringGenerator generator, String accessToken, ResultMatcher statusMatcher, String headerKey, String headerValue) throws Exception {
        String clientId = generator.generate();
        UaaClientDetails client = new UaaClientDetails(clientId, null, null, "client_credentials", null);
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
}
