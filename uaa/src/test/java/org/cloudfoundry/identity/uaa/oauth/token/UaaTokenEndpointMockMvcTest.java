package org.cloudfoundry.identity.uaa.oauth.token;

import org.cloudfoundry.identity.uaa.mock.token.AbstractTokenMockMvcTests;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.common.util.OAuth2Utils;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_PASSWORD;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.TokenFormat.OPAQUE;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class UaaTokenEndpointMockMvcTest extends AbstractTokenMockMvcTests {
    private static final String CLIENTID = "oauth_showcase_password_grant";
    private static final String CLIENTSECRET = "secret";

    @Test
    void methodNotAllowedReturnsError_PUT() throws Exception {
        String username = createUserForPasswordGrant(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, generator);
        mockMvc.perform(
                put("/oauth/token")
                        .param("client_id", CLIENTID)
                        .param("client_secret", CLIENTSECRET)
                        .param(OAuth2Utils.GRANT_TYPE, GRANT_TYPE_PASSWORD)
                        .param("username", username)
                        .param("password", SECRET)
                        .param(TokenConstants.REQUEST_TOKEN_FORMAT, OPAQUE.getStringValue())
                        .param("response_type", "id_token")
                        .accept(APPLICATION_JSON)
                        .contentType(APPLICATION_FORM_URLENCODED))
                .andExpect(status().isMethodNotAllowed())
                .andExpect(jsonPath("$.error").value("method_not_allowed"))
                .andExpect(jsonPath("$.error_description").value("Request method 'PUT' not supported"));
    }

    @Test
    void methodNotAllowedReturnsError_DELETE() throws Exception {
        String username = createUserForPasswordGrant(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, generator);
        mockMvc.perform(
                delete("/oauth/token")
                        .param("client_id", CLIENTID)
                        .param("client_secret", CLIENTSECRET)
                        .param(OAuth2Utils.GRANT_TYPE, GRANT_TYPE_PASSWORD)
                        .param("username", username)
                        .param("password", SECRET)
                        .param(TokenConstants.REQUEST_TOKEN_FORMAT, OPAQUE.getStringValue())
                        .param("response_type", "id_token")
                        .accept(APPLICATION_JSON)
                        .contentType(APPLICATION_FORM_URLENCODED))
                .andExpect(status().isMethodNotAllowed())
                .andExpect(jsonPath("$.error").value("method_not_allowed"))
                .andExpect(jsonPath("$.error_description").value("Request method 'DELETE' not supported"));
    }
}
