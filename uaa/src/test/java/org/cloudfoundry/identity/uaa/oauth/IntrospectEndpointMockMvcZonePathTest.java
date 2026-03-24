package org.cloudfoundry.identity.uaa.oauth;

import com.fasterxml.jackson.core.type.TypeReference;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.mock.util.ZoneResolutionMode;
import org.cloudfoundry.identity.uaa.mock.token.AbstractTokenMockMvcTests;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.token.TokenConstants;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils;
import org.springframework.http.HttpMethod;
import org.cloudfoundry.identity.uaa.extensions.EnabledIfZonePathsEnabled;

import java.util.Map;
import java.util.Objects;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_PASSWORD;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.TokenFormat.OPAQUE;
import static org.springframework.http.HttpHeaders.ACCEPT;
import static org.springframework.http.HttpHeaders.CONTENT_TYPE;
import static org.springframework.http.MediaType.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@EnabledIfZonePathsEnabled
class IntrospectEndpointMockMvcZonePathTest extends AbstractTokenMockMvcTests {

    private static final String CLIENT_ID = "oauth_showcase_password_grant";
    private static final String CLIENT_SECRET = "secret";
    private String userAccessToken;

    @BeforeEach
    void setUp() throws Exception {
        String username = createUserForPasswordGrant(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, generator);

        String tokenEndpointResponse = mockMvc.perform(
                post("/oauth/token")
                        .param("client_id", CLIENT_ID)
                        .param("client_secret", CLIENT_SECRET)
                        .param(OAuth2Utils.GRANT_TYPE, GRANT_TYPE_PASSWORD)
                        .param("username", username)
                        .param("password", SECRET)
                        .param(TokenConstants.REQUEST_TOKEN_FORMAT, OPAQUE.getStringValue())
                        .param("response_type", "id_token")
                        .accept(APPLICATION_JSON)
                        .contentType(APPLICATION_FORM_URLENCODED))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        userAccessToken = Objects.requireNonNull(JsonUtils.readValue(tokenEndpointResponse, OAuth2AccessToken.class)).getValue();
    }

    @Test
    void validToken() throws Exception {
        mockMvc.perform(
                post("/introspect")
                        .with(httpBasic(CLIENT_ID, CLIENT_SECRET))
                        .header(ACCEPT, APPLICATION_JSON_VALUE)
                        .header(CONTENT_TYPE, APPLICATION_FORM_URLENCODED_VALUE)
                        .param("token", userAccessToken))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.active").value("true"))
                .andExpect(jsonPath("$.client_id").value(CLIENT_ID))
                .andExpect(content().contentType(APPLICATION_JSON));
    }

    @Test
    void invalidToken() throws Exception {
        mockMvc.perform(
                post("/introspect")
                        .with(httpBasic(CLIENT_ID, CLIENT_SECRET))
                        .header(ACCEPT, APPLICATION_JSON_VALUE)
                        .header(CONTENT_TYPE, APPLICATION_FORM_URLENCODED_VALUE)
                        .param("token", "invalid-token"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.active").value("false"))
                .andExpect(content().contentType(APPLICATION_JSON));
    }

    @Test
    void deleteNotSupported() throws Exception {
        mockMvc.perform(
                delete("/introspect")
                        .with(httpBasic(CLIENT_ID, CLIENT_SECRET))
                        .header(ACCEPT, APPLICATION_JSON_VALUE)
                        .header(CONTENT_TYPE, APPLICATION_FORM_URLENCODED_VALUE)
                        .param("token", userAccessToken))
                .andDo(print())
                .andExpect(status().isMethodNotAllowed())
                .andExpect(jsonPath("$.error").value("method_not_allowed"))
                .andExpect(jsonPath("$.error_description").value("Request method 'DELETE' is not supported"));
    }

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void introspect_within_zone(ZoneResolutionMode mode) throws Exception {
        String subdomain = generator.generate().toLowerCase();
        UaaClientDetails resourceClient = new UaaClientDetails("introspect-client", "", "uaa.user", "password", "uaa.resource", "http://redirect");
        resourceClient.setClientSecret("secret");
        MockMvcUtils.IdentityZoneCreationResult result = MockMvcUtils.createOtherIdentityZoneAndReturnResult(subdomain, mockMvc, webApplicationContext, resourceClient, IdentityZoneHolder.getCurrentZoneId());

        String username = "user" + generator.generate().toLowerCase();
        ScimUser user = new ScimUser(null, username, "Given", "Family");
        user.setPrimaryEmail(username + "@test.org");
        user.setPassword(SECRET);
        user = MockMvcUtils.createUserInZone(mockMvc, result.getZoneAdminToken(), user, "", result.getIdentityZone().getId());

        String tokenResponse = mockMvc.perform(mode.createRequestBuilder(subdomain, HttpMethod.POST, "/oauth/token")
                        .with(httpBasic("introspect-client", "secret"))
                        .param("grant_type", GRANT_TYPE_PASSWORD)
                        .param("username", username)
                        .param("password", SECRET)
                        .param(TokenConstants.REQUEST_TOKEN_FORMAT, OPAQUE.getStringValue())
                        .accept(APPLICATION_JSON)
                        .contentType(APPLICATION_FORM_URLENCODED))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        String zoneToken = JsonUtils.readValue(tokenResponse, new TypeReference<Map<String, Object>>() {}).get("access_token").toString();

        mockMvc.perform(mode.createRequestBuilder(subdomain, HttpMethod.POST, "/introspect")
                        .with(httpBasic("introspect-client", "secret"))
                        .header(ACCEPT, APPLICATION_JSON_VALUE)
                        .header(CONTENT_TYPE, APPLICATION_FORM_URLENCODED_VALUE)
                        .param("token", zoneToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.active").value("true"))
                .andExpect(jsonPath("$.client_id").value("introspect-client"))
                .andExpect(content().contentType(APPLICATION_JSON));
    }
}
