package org.cloudfoundry.identity.uaa.oauth;

import com.fasterxml.jackson.core.type.TypeReference;
import org.apache.commons.codec.binary.Base64;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.mock.util.ZoneResolutionMode;
import org.cloudfoundry.identity.uaa.mock.token.AbstractTokenMockMvcTests;
import org.cloudfoundry.identity.uaa.oauth.token.TokenConstants;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.ResultMatcher;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.cloudfoundry.identity.uaa.extensions.EnabledIfZonePathsEnabled;

import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.scim.ScimUser;

import java.util.Map;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_PASSWORD;
import static org.springframework.http.HttpHeaders.ACCEPT;
import static org.springframework.http.HttpHeaders.CONTENT_TYPE;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED_VALUE;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@EnabledIfZonePathsEnabled
class CheckTokenEndpointMockMvcZonePathTest extends AbstractTokenMockMvcTests {
    private String token;
    private String idToken;
    private String basic;
    private boolean allowQueryString;

    @Autowired
    private CheckTokenEndpoint checkTokenEndpoint;

    @BeforeEach
    void get_token_to_check() throws Exception {
        String username = createUserForPasswordGrant(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, generator);

        String clientId = "oauth_showcase_password_grant";
        String clientSecret = "secret";
        String content = mockMvc.perform(
                post("/oauth/token")
                        .param("client_id", clientId)
                        .param("client_secret", clientSecret)
                        .param(OAuth2Utils.GRANT_TYPE, GRANT_TYPE_PASSWORD)
                        .param("username", username)
                        .param("password", SECRET)
                        .param(TokenConstants.REQUEST_TOKEN_FORMAT, TokenConstants.TokenFormat.OPAQUE.getStringValue())
                        .param("response_type", "id_token")
                        .accept(APPLICATION_JSON)
                        .contentType(APPLICATION_FORM_URLENCODED))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        Map<String, Object> tokenMap = JsonUtils.readValue(content, new TypeReference<Map<String, Object>>() {
        });
        token = (String) tokenMap.get("access_token");
        idToken = (String) tokenMap.get("id_token");
        basic = new String(Base64.encodeBase64((clientId + ":" + clientSecret).getBytes()));
        allowQueryString = checkTokenEndpoint.isAllowQueryString();
        checkTokenEndpoint.setAllowQueryString(false);
    }

    @AfterEach
    void resetAllowQueryString() {
        checkTokenEndpoint.setAllowQueryString(allowQueryString);
    }

    @Test
    void check_token_get() throws Exception {
        check_token(get("/check_token"), status().isMethodNotAllowed())
                .andExpect(jsonPath("$.error").value("method_not_allowed"))
                .andExpect(jsonPath("$.error_description").value("Request method 'GET' is not supported"));

    }

    @Test
    void check_token_put() throws Exception {
        check_token(put("/check_token"), status().isMethodNotAllowed())
                .andExpect(jsonPath("$.error").value("method_not_allowed"))
                .andExpect(jsonPath("$.error_description").value("Request method 'PUT' is not supported"));

    }

    @Test
    void check_token_post() throws Exception {
        check_token(post("/check_token"), status().isOk());
    }

    @Test
    void check_token_get_when_allowed() throws Exception {
        checkTokenEndpoint.setAllowQueryString(true);
        get_check_token(status().isOk());
    }

    @Test
    void check_token_delete() throws Exception {
        check_token(MockMvcRequestBuilders.delete("/check_token"), status().isMethodNotAllowed())
                .andExpect(jsonPath("$.error").value("method_not_allowed"))
                .andExpect(jsonPath("$.error_description").value("Request method 'DELETE' is not supported"));
    }

    @Test
    void check_token_endpoint_post_query_string() throws Exception {
        mockMvc.perform(
                post("/check_token?token={token}", token)
                        .header("Authorization", "Basic " + basic)
                        .header(ACCEPT, APPLICATION_JSON_VALUE)
                        .header(CONTENT_TYPE, APPLICATION_FORM_URLENCODED_VALUE))
                .andExpect(status().isNotAcceptable())
                .andExpect(header().string(CONTENT_TYPE, APPLICATION_JSON_VALUE))
                .andExpect(jsonPath("$.error").value("query_string_not_allowed"))
                .andExpect(jsonPath("$.error_description").value("Parameters must be passed in the body of the request"));
    }

    @Test
    void check_token_endpoint_id_token() throws Exception {
        mockMvc.perform(
                post("/check_token")
                        .header("Authorization", "Basic " + basic)
                        .header(ACCEPT, APPLICATION_JSON_VALUE)
                        .header(CONTENT_TYPE, APPLICATION_FORM_URLENCODED_VALUE)
                        .param("token", idToken))
                .andExpect(status().isOk());
    }

    ResultActions check_token(MockHttpServletRequestBuilder builder, ResultMatcher matcher) throws Exception {
        return mockMvc.perform(
                builder
                        .header("Authorization", "Basic " + basic)
                        .header(ACCEPT, APPLICATION_JSON_VALUE)
                        .header(CONTENT_TYPE, APPLICATION_FORM_URLENCODED_VALUE)
                        .param("token", token))
                .andExpect(matcher)
                .andExpect(header().string(CONTENT_TYPE, APPLICATION_JSON_VALUE));
    }

    ResultActions get_check_token(ResultMatcher matcher) throws Exception {
        return mockMvc.perform(
                get("/check_token?token={token}", token)
                        .header("Authorization", "Basic " + basic)
                        .header(ACCEPT, APPLICATION_JSON_VALUE)
                        .header(CONTENT_TYPE, APPLICATION_FORM_URLENCODED_VALUE))
                .andExpect(matcher)
                .andExpect(header().string(CONTENT_TYPE, APPLICATION_JSON_VALUE));
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void check_token_within_zone(ZoneResolutionMode mode) throws Exception {
        String subdomain = generator.generate().toLowerCase();
        UaaClientDetails resourceClient = new UaaClientDetails("check-token-client", "", "uaa.user", "password", "uaa.resource", "http://redirect");
        resourceClient.setClientSecret("secret");
        MockMvcUtils.IdentityZoneCreationResult result = MockMvcUtils.createOtherIdentityZoneAndReturnResult(subdomain, mockMvc, webApplicationContext, resourceClient, IdentityZoneHolder.getCurrentZoneId());

        String username = "user" + generator.generate().toLowerCase();
        ScimUser user = new ScimUser(null, username, "Given", "Family");
        user.setPrimaryEmail(username + "@test.org");
        user.setPassword(SECRET);
        user = MockMvcUtils.createUserInZone(mockMvc, result.getZoneAdminToken(), user, "", result.getIdentityZone().getId());

        String tokenResponse = mockMvc.perform(mode.createRequestBuilder(subdomain, HttpMethod.POST, "/oauth/token")
                        .with(org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic("check-token-client", "secret"))
                        .param("grant_type", GRANT_TYPE_PASSWORD)
                        .param("username", username)
                        .param("password", SECRET)
                        .param(TokenConstants.REQUEST_TOKEN_FORMAT, TokenConstants.TokenFormat.OPAQUE.getStringValue())
                        .accept(APPLICATION_JSON)
                        .contentType(APPLICATION_FORM_URLENCODED))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        String zoneToken = JsonUtils.readValue(tokenResponse, new TypeReference<Map<String, Object>>() {}).get("access_token").toString();

        String zoneBasic = new String(Base64.encodeBase64(("check-token-client:secret").getBytes()));
        mockMvc.perform(mode.createRequestBuilder(subdomain, HttpMethod.POST, "/check_token")
                        .header("Authorization", "Basic " + zoneBasic)
                        .header(ACCEPT, APPLICATION_JSON_VALUE)
                        .header(CONTENT_TYPE, APPLICATION_FORM_URLENCODED_VALUE)
                        .param("token", zoneToken))
                .andExpect(status().isOk())
                .andExpect(header().string(CONTENT_TYPE, APPLICATION_JSON_VALUE))
                .andExpect(jsonPath("$.user_name").value(username));
    }
}
