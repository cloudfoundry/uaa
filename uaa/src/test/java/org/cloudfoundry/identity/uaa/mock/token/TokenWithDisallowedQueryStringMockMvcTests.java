package org.cloudfoundry.identity.uaa.mock.token;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_PASSWORD;
import static org.springframework.http.HttpHeaders.CONTENT_TYPE;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.oauth.refresh.RefreshTokenCreator;
import org.cloudfoundry.identity.uaa.provider.saml.idp.SamlTestUtils;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupMembershipManager;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimUserProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

@DefaultTestContext
@TestPropertySource(properties = {
    "jwt.token.queryString.enabled=false"
})
public class TokenWithDisallowedQueryStringMockMvcTests extends AbstractTokenMockMvcTests {
    protected RandomValueStringGenerator generator = new RandomValueStringGenerator();

    @Autowired
    private MockMvc mockMvc;

    private String username;

    @BeforeEach
    void setUp(
        final @Autowired JdbcScimUserProvisioning jdbcScimUserProvisioning,
        final @Autowired JdbcScimGroupMembershipManager jdbcScimGroupMembershipManager,
        final @Autowired JdbcScimGroupProvisioning jdbcScimGroupProvisioning) {
        username = createUserForPasswordGrant(
            jdbcScimUserProvisioning,
            jdbcScimGroupMembershipManager,
            jdbcScimGroupProvisioning,
            generator);
    }

    @Test
    public void token_endpoint_get() throws Exception {
        username = createUserForPasswordGrant(
            jdbcScimUserProvisioning,
            jdbcScimGroupMembershipManager,
            jdbcScimGroupProvisioning,
            generator);

        mockMvc.perform(
            get("/oauth/token")
                .param("client_id", "cf")
                .param("client_secret", "")
                .param(OAuth2Utils.GRANT_TYPE, GRANT_TYPE_PASSWORD)
                .param("username", username)
                .param("password", SECRET)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_FORM_URLENCODED))
               .andDo(print())
               .andExpect(status().isMethodNotAllowed())
               .andExpect(header().string(CONTENT_TYPE, APPLICATION_JSON_VALUE))
               .andExpect(jsonPath("$.error").value("method_not_allowed"))
               .andExpect(jsonPath("$.error_description").value("Request method 'GET' not supported"));
    }

    @Test
    void token_endpoint_post_query_string() throws Exception {
        mockMvc.perform(
            post("/oauth/token?client_id=cf&client_secret=&grant_type=password&username={username}&password=secret", username)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_FORM_URLENCODED))
               .andExpect(status().isNotAcceptable())
               .andExpect(header().string(CONTENT_TYPE, APPLICATION_JSON_VALUE))
               .andExpect(jsonPath("$.error").value("query_string_not_allowed"))
               .andExpect(jsonPath("$.error_description").value("Parameters must be passed in the body of the request"));
    }
}
