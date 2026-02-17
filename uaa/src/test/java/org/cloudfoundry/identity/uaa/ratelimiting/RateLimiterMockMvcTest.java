package org.cloudfoundry.identity.uaa.ratelimiting;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.util.SetServerNameRequestPostProcessor;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.web.context.WebApplicationContext;

import static org.cloudfoundry.identity.uaa.test.UaaTestAccounts.getAuthorizationHeader;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@DefaultTestContext
public class RateLimiterMockMvcTest {

    @Autowired
    WebApplicationContext webApplicationContext;
    @Autowired
    MockMvc mockMvc;
    @Autowired
    private TestClient testClient;

    private String adminToken;
    private String noUaaAdminToken;
    private String loginClientToken;
    MockMvcUtils.IdentityZoneCreationResult zone;
    @BeforeEach
    void setUp() throws Exception {
        adminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret", "uaa.admin");
        noUaaAdminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret", "clients.read clients.write clients.secret scim.read scim.write clients.admin");
        loginClientToken = testClient.getClientCredentialsOAuthAccessToken("login", "loginsecret", "");

        UaaClientDetails zoneAdminClient = new UaaClientDetails("admin", null, "", "client_credentials", "uaa.admin,uaa.none", "http://redirect");
        zoneAdminClient.setClientSecret("adminsecret");
        zone = MockMvcUtils.createOtherIdentityZoneAndReturnResult("ratelimit-zone-" + System.nanoTime(), mockMvc, webApplicationContext, zoneAdminClient, IdentityZoneHolder.getCurrentZoneId());
    }

    @AfterEach
    void clearSecContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    public void happyTokenPathWithoutSlash() throws Exception {
        MockHttpServletRequestBuilder get = get("/RateLimitingStatus")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON);

        mockMvc.perform(get)
                .andExpect(status().isOk())
                .andExpect(jsonPath("current.status").hasJsonPath());
    }

    @Test
    public void happyTokenPathWithSlash() throws Exception {
        MockHttpServletRequestBuilder get = get("/RateLimitingStatus/")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON);

        mockMvc.perform(get)
                .andExpect(status().isOk())
                .andExpect(jsonPath("current.status").hasJsonPath());
    }

    @Test
    public void failBasicAuthPathWithSlash() throws Exception {
        MockHttpServletRequestBuilder get = get("/RateLimitingStatus/")
                .header("Authorization", getAuthorizationHeader("admin", "adminsecret"))
                .accept(APPLICATION_JSON);

        mockMvc.perform(get)
                .andExpect(status().isUnauthorized());
    }

    @Test
    public void failBasicAuthPathWithoutSlash() throws Exception {
        MockHttpServletRequestBuilder get = get("/RateLimitingStatus")
                .header("Authorization", getAuthorizationHeader("admin", "adminsecret"))
                .accept(APPLICATION_JSON);

        mockMvc.perform(get)
                .andExpect(status().isUnauthorized());
    }

    @Test
    public void improperClientWithoutScopeShouldFail() throws Exception {
        MockHttpServletRequestBuilder get = get("/RateLimitingStatus")
                .header("Authorization", "Bearer " + loginClientToken)
                .accept(APPLICATION_JSON);

        mockMvc.perform(get)
                .andExpect(status().isForbidden());
    }

    @Test
    public void missingScopeInTokenShouldFail() throws Exception {
        MockHttpServletRequestBuilder get = get("/RateLimitingStatus")
                .header("Authorization", "Bearer " + noUaaAdminToken)
                .accept(APPLICATION_JSON);

        mockMvc.perform(get)
                .andExpect(status().isForbidden());
    }

    @Test
    public void improperClientBasicAuthShouldFail() throws Exception {
        MockHttpServletRequestBuilder get = get("/RateLimitingStatus")
                .header("Authorization", getAuthorizationHeader("login", "loginsecret"))
                .accept(APPLICATION_JSON);

        mockMvc.perform(get)
                .andExpect(status().isUnauthorized());
    }

    @Test
    public void improperClientTokenAuthShouldFail() throws Exception {
        MockHttpServletRequestBuilder get = get("/RateLimitingStatus")
                .header("Authorization", "Bearer " + loginClientToken)
                .accept(APPLICATION_JSON);

        mockMvc.perform(get)
                .andExpect(status().isForbidden());
    }

    @Test
    public void zoneClientTokenAuthShouldFail() throws Exception {
        MockHttpServletRequestBuilder get = get("/RateLimitingStatus")
                .with(new SetServerNameRequestPostProcessor(zone.getIdentityZone().getSubdomain() + ".localhost"))
                .header("Authorization", "Bearer " + zone.getZoneAdminToken())
                .accept(APPLICATION_JSON);

        mockMvc.perform(get)
                .andExpect(status().isUnauthorized());
    }

    @Test
    public void zoneUaaAdminClientTokenAuthShouldFail() throws Exception {
        String zoneUaaAdminToken = MockMvcUtils.getClientCredentialsOAuthAccessToken(
                mockMvc, "admin", "adminsecret", "uaa.admin", zone.getIdentityZone().getSubdomain(), false
        );
        MockHttpServletRequestBuilder get = get("/RateLimitingStatus")
                .with(new SetServerNameRequestPostProcessor(zone.getIdentityZone().getSubdomain() + ".localhost"))
                .header("Authorization", "Bearer " + zoneUaaAdminToken)
                .accept(APPLICATION_JSON);

        mockMvc.perform(get)
                .andExpect(status().isForbidden());
    }

    @Test
    public void zoneClientBasicAuthShouldFail() throws Exception {
        MockHttpServletRequestBuilder get = get("/RateLimitingStatus")
                .with(new SetServerNameRequestPostProcessor(zone.getIdentityZone().getSubdomain() + ".localhost"))
                .header("Authorization", getAuthorizationHeader("admin", "adminsecret"))
                .accept(APPLICATION_JSON);

        mockMvc.perform(get)
                .andExpect(status().isUnauthorized());
    }
}
