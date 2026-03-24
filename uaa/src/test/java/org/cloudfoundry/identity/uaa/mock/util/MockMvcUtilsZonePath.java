/*
 * Helper for ZonePath MockMvc tests. Provides zone-resolution-aware overloads that use
 * {@link org.cloudfoundry.identity.uaa.util.ZoneResolutionMode} (from server test).
 * Keep MockMvcUtils restored to develop; only ZonePath-named code references ZoneResolutionMode.
 */
package org.cloudfoundry.identity.uaa.mock.util;

import org.cloudfoundry.identity.uaa.mock.util.ZoneResolutionMode;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter;
import org.springframework.http.HttpMethod;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.cloudfoundry.identity.uaa.oauth.token.TokenConstants;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.util.JsonUtils;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.TokenFormat.OPAQUE;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.util.StringUtils.hasText;

public final class MockMvcUtilsZonePath {

    private MockMvcUtilsZonePath() {
    }

    public static String getClientCredentialsOAuthAccessToken(ZoneResolutionMode mode,
            MockMvc mockMvc,
            String clientId,
            String clientSecret,
            String scope,
            String subdomain,
            boolean opaque) throws Exception {
        MockHttpServletRequestBuilder oauthTokenPost = mode.createRequestBuilder(subdomain != null ? subdomain : "", HttpMethod.POST, "/oauth/token")
                .with(httpBasic(clientId, clientSecret))
                .param("grant_type", "client_credentials")
                .param("client_id", clientId)
                .param("revocable", "true");
        if (hasText(scope)) {
            oauthTokenPost.param("scope", scope);
        }
        if (opaque) {
            oauthTokenPost.param(TokenConstants.REQUEST_TOKEN_FORMAT, OPAQUE.getStringValue());
        }
        MvcResult result = mockMvc.perform(oauthTokenPost)
                .andDo(print())
                .andExpect(status().isOk())
                .andReturn();
        OAuthToken oauthToken = JsonUtils.readValue(result.getResponse().getContentAsString(), OAuthToken.class);
        return oauthToken.accessToken;
    }

    public static ScimUser createUserInZone(ZoneResolutionMode mode, MockMvc mockMvc, String accessToken, ScimUser user, String subdomain, String zoneId) throws Exception {
        MockHttpServletRequestBuilder post = mode.createRequestBuilder(subdomain, HttpMethod.POST, "/Users");
        post.header("Authorization", "Bearer " + accessToken)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsBytes(user));
        if (hasText(zoneId)) {
            post.header(IdentityZoneSwitchingFilter.HEADER, zoneId);
        }
        MvcResult userResult = mockMvc.perform(post)
                .andExpect(status().isCreated()).andReturn();
        return JsonUtils.readValue(userResult.getResponse().getContentAsString(), ScimUser.class);
    }

    public static ScimUser readUserInZone(ZoneResolutionMode mode, MockMvc mockMvc, String accessToken, String userId, String subdomain, String zoneId) throws Exception {
        MockHttpServletRequestBuilder get = mode.createRequestBuilder(subdomain, HttpMethod.GET, "/Users/" + userId);
        get.header("Authorization", "Bearer " + accessToken)
                .accept(APPLICATION_JSON);
        if (hasText(zoneId)) {
            get.header(IdentityZoneSwitchingFilter.HEADER, zoneId);
        }
        MvcResult userResult = mockMvc.perform(get)
                .andExpect(status().isOk()).andReturn();
        return JsonUtils.readValue(userResult.getResponse().getContentAsString(), ScimUser.class);
    }
}
