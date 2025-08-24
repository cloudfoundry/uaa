package org.cloudfoundry.identity.uaa.test;

import org.apache.commons.codec.binary.Base64;
import org.cloudfoundry.identity.uaa.mock.util.OAuthToken;
import org.cloudfoundry.identity.uaa.oauth.token.TokenConstants;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.SetServerNameRequestPostProcessor;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.TokenFormat.OPAQUE;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class TestClient {
    private final MockMvc mockMvc;

    public TestClient(MockMvc mockMvc) {
        this.mockMvc = mockMvc;
    }

    public String getClientCredentialsOAuthAccessToken(String clientId, String clientSecret, String scope) throws Exception {
        return getClientCredentialsOAuthAccessToken(clientId, clientSecret, scope, null);
    }

    public String getClientCredentialsOAuthAccessToken(String clientId, String clientSecret, String scope, String subdomain)
            throws Exception {
        String basicDigestHeaderValue = "Basic "
                + new String(Base64.encodeBase64((clientId + ":" + clientSecret).getBytes()));
        MockHttpServletRequestBuilder oauthTokenPost = post("/oauth/token")
                .header("Authorization", basicDigestHeaderValue)
                .param("grant_type", "client_credentials")
                .param("client_id", clientId)
                .param(TokenConstants.REQUEST_TOKEN_FORMAT, OPAQUE.getStringValue())
                .param("scope", scope);
        if (subdomain != null && !"".equals(subdomain)) {
            oauthTokenPost.with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"));
        }
        MvcResult result = mockMvc.perform(oauthTokenPost)
                .andExpect(status().isOk())
                .andReturn();
        OAuthToken oauthToken = JsonUtils.readValue(result.getResponse().getContentAsString(), OAuthToken.class);
        return oauthToken.accessToken;
    }

    public String getUserOAuthAccessToken(String clientId, String clientSecret, String username, String password, String scope)
            throws Exception {
        MockHttpServletRequestBuilder oauthTokenPost = post("/oauth/token")
                .with(httpBasic(clientId, clientSecret))
                .param("grant_type", "password")
                .param("client_id", clientId)
                .param("username", username)
                .param("password", password)
                .param(TokenConstants.REQUEST_TOKEN_FORMAT, OPAQUE.getStringValue())
                .param("scope", scope);
        MvcResult result = mockMvc.perform(oauthTokenPost).andExpect(status().isOk()).andReturn();
        OAuthToken oauthToken = JsonUtils.readValue(result.getResponse().getContentAsString(), OAuthToken.class);
        return oauthToken.accessToken;
    }

    public String getUserOAuthAccessTokenForZone(String clientId, String clientSecret, String username, String password, String scope, String subdomain) throws Exception {
        MockHttpServletRequestBuilder oauthTokenPost = post("/oauth/token")
                .with(httpBasic(clientId, clientSecret))
                .param("grant_type", "password")
                .param("client_id", clientId)
                .param("username", username)
                .param("password", password)
                .param(TokenConstants.REQUEST_TOKEN_FORMAT, TokenConstants.TokenFormat.JWT.getStringValue())
                .param("scope", scope);
        oauthTokenPost.header("Host", subdomain + ".localhost");
        MvcResult result = mockMvc.perform(oauthTokenPost).andExpect(status().isOk()).andReturn();
        OAuthToken oauthToken = JsonUtils.readValue(result.getResponse().getContentAsString(), OAuthToken.class);
        return oauthToken.accessToken;
    }
}
