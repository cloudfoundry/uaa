package org.cloudfoundry.identity.uaa.ratelimiting;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.test.TestClient;
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
    @BeforeEach
    void setUp() throws Exception {
        adminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret", "uaa.admin");
        noUaaAdminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret", "clients.read clients.write clients.secret scim.read scim.write clients.admin");
        loginClientToken = testClient.getClientCredentialsOAuthAccessToken("login", "loginsecret", "");

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
    public void happyBasicAuthPathWithoutSlash() throws Exception {
        MockHttpServletRequestBuilder get = get("/RateLimitingStatus")
                .header("Authorization", getAuthorizationHeader("admin", "adminsecret"))
                .accept(APPLICATION_JSON);

        mockMvc.perform(get)
                .andExpect(status().isOk())
                .andExpect(jsonPath("current.status").hasJsonPath());
    }

    @Test
    public void improperScopeShouldFail() throws Exception {
        MockHttpServletRequestBuilder get = get("/RateLimitingStatus")
                .header("Authorization", "Bearer " + loginClientToken)
                .accept(APPLICATION_JSON);

        mockMvc.perform(get)
                .andExpect(status().isForbidden()); //TODO, should it not be 401, it's a valid token
    }

    @Test
    public void improperClientShouldFail() throws Exception {
        MockHttpServletRequestBuilder get = get("/RateLimitingStatus")
                .header("Authorization", getAuthorizationHeader("login", "adminsecret"))
                .accept(APPLICATION_JSON);

        mockMvc.perform(get)
                .andExpect(status().isUnauthorized());
    }
}
