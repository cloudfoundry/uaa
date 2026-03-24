package org.cloudfoundry.identity.uaa.ratelimiting;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtilsZonePath;
import org.cloudfoundry.identity.uaa.mock.util.ZoneResolutionMode;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.context.WebApplicationContext;
import org.cloudfoundry.identity.uaa.extensions.EnabledIfZonePathsEnabled;

import static org.cloudfoundry.identity.uaa.test.UaaTestAccounts.getAuthorizationHeader;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@DefaultTestContext
@EnabledIfZonePathsEnabled
public class RateLimitingFilterZonePathMockMvcTest {

    @Autowired
    WebApplicationContext webApplicationContext;
    @Autowired
    MockMvc mockMvc;
    @Autowired
    private TestClient testClient;

    private String adminToken;
    private String loginClientToken;

    private String subdomain;

    @BeforeEach
    void setUp() throws Exception {
        adminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret", "uaa.admin");
        loginClientToken = testClient.getClientCredentialsOAuthAccessToken("login", "loginsecret", "");
        subdomain = "ratelimit-zone-" + System.nanoTime();
        UaaClientDetails adminClient = new UaaClientDetails("admin", null, "", "client_credentials", "uaa.admin,uaa.none", "http://redirect");
        adminClient.setClientSecret("adminsecret");
        MockMvcUtils.createOtherIdentityZoneAndReturnResult(subdomain, mockMvc, webApplicationContext, adminClient, IdentityZoneHolder.getCurrentZoneId());
    }

    @AfterEach
    void clearSecContext() {
        SecurityContextHolder.clearContext();
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void happyTokenPathWithoutSlash(ZoneResolutionMode mode) throws Exception {
        String adminToken = MockMvcUtilsZonePath.getClientCredentialsOAuthAccessToken(mode, mockMvc, "admin", "adminsecret", "uaa.admin", subdomain, false);
        mockMvc.perform(mode.createRequestBuilder(subdomain, HttpMethod.GET, "/RateLimitingStatus")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON))
                .andExpect(status().isForbidden());
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void happyTokenPathWithSlash(ZoneResolutionMode mode) throws Exception {
        String adminToken = MockMvcUtilsZonePath.getClientCredentialsOAuthAccessToken(mode, mockMvc, "admin", "adminsecret", "uaa.admin", subdomain, false);
        mockMvc.perform(mode.createRequestBuilder(subdomain, HttpMethod.GET, "/RateLimitingStatus/")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON))
                .andExpect(status().isForbidden());
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void happyBasicAuthPathWithoutSlash(ZoneResolutionMode mode) throws Exception {
        String adminToken = MockMvcUtilsZonePath.getClientCredentialsOAuthAccessToken(mode, mockMvc, "admin", "adminsecret", "uaa.admin", subdomain, false);
        mockMvc.perform(mode.createRequestBuilder(subdomain, HttpMethod.GET, "/RateLimitingStatus")
                .header("Authorization", "Bearer " + adminToken)
                .accept(APPLICATION_JSON))
                        .andDo(print())
                .andExpect(status().isForbidden());
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void improperScopeShouldFail(ZoneResolutionMode mode) throws Exception {
        String tokenWithoutUaaAdmin = loginClientToken;
        mockMvc.perform(mode.createRequestBuilder(subdomain, HttpMethod.GET, "/RateLimitingStatus")
                .header("Authorization", "Bearer " + tokenWithoutUaaAdmin)
                .accept(APPLICATION_JSON))
                .andExpect(status().isUnauthorized());
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void improperClientShouldFail(ZoneResolutionMode mode) throws Exception {
        mockMvc.perform(mode.createRequestBuilder(subdomain, HttpMethod.GET, "/RateLimitingStatus")
                .header("Authorization", getAuthorizationHeader("login", "adminsecret"))
                .accept(APPLICATION_JSON))
                .andExpect(status().isUnauthorized());
    }
}
