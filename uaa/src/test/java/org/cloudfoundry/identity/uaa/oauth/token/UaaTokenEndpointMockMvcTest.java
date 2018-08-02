package org.cloudfoundry.identity.uaa.oauth.token;

import org.cloudfoundry.identity.uaa.mock.token.AbstractTokenMockMvcTests;
import org.junit.Test;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.web.util.HtmlUtils;

import static org.cloudfoundry.identity.uaa.oauth.TokenTestSupport.PASSWORD;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.TokenFormat.OPAQUE;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class UaaTokenEndpointMockMvcTest extends AbstractTokenMockMvcTests {
    public static final String CLIENTID = "oauth_showcase_password_grant";
    public static final String CLIENTSECRET = "secret";

    @Test
    public void methodNotAllowedReturnsError_PUT() throws Exception {
        String username = setUpUserForPasswordGrant();
        getMockMvc().perform(
            put("/oauth/token")
                .param("client_id", CLIENTID)
                .param("client_secret", CLIENTSECRET)
                .param(OAuth2Utils.GRANT_TYPE, PASSWORD)
                .param("username", username)
                .param("password", SECRET)
                .param(TokenConstants.REQUEST_TOKEN_FORMAT, OPAQUE.getStringValue())
                .param("response_type", "id_token")
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_FORM_URLENCODED))
            .andExpect(status().isMethodNotAllowed())
            .andExpect(jsonPath("$.error").value("method_not_allowed"))
            .andExpect(jsonPath("$.error_description").value(HtmlUtils.htmlEscape("Request method 'PUT' not supported", "ISO-8859-1")));
    }

    @Test
    public void methodNotAllowedReturnsError_DELETE() throws Exception {
        String username = setUpUserForPasswordGrant();
        getMockMvc().perform(
            delete("/oauth/token")
                .param("client_id", CLIENTID)
                .param("client_secret", CLIENTSECRET)
                .param(OAuth2Utils.GRANT_TYPE, PASSWORD)
                .param("username", username)
                .param("password", SECRET)
                .param(TokenConstants.REQUEST_TOKEN_FORMAT, OPAQUE.getStringValue())
                .param("response_type", "id_token")
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_FORM_URLENCODED))
            .andExpect(status().isMethodNotAllowed())
            .andExpect(jsonPath("$.error").value("method_not_allowed"))
            .andExpect(jsonPath("$.error_description").value(HtmlUtils.htmlEscape("Request method 'DELETE' not supported", "ISO-8859-1")));
    }
}
