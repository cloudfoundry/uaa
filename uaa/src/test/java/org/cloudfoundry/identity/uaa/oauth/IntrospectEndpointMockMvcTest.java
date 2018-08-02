package org.cloudfoundry.identity.uaa.oauth;

import java.util.Map;

import org.cloudfoundry.identity.uaa.mock.token.AbstractTokenMockMvcTests;
import org.cloudfoundry.identity.uaa.oauth.token.TokenConstants;
import org.cloudfoundry.identity.uaa.util.JsonUtils;

import com.fasterxml.jackson.core.type.TypeReference;
import org.apache.commons.codec.binary.Base64;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.web.util.HtmlUtils;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_PASSWORD;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.TokenFormat.OPAQUE;
import static org.springframework.http.HttpHeaders.ACCEPT;
import static org.springframework.http.HttpHeaders.CONTENT_TYPE;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED_VALUE;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.log;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class IntrospectEndpointMockMvcTest extends AbstractTokenMockMvcTests {

    public static final String CLIENTID = "oauth_showcase_password_grant";
    public static final String CLIENTSECRET = "secret";
    private String token;
    private String basic;

    @Before
    public void get_token_to_check() throws Exception {
        String username = setUpUserForPasswordGrant();

        String content = getMockMvc().perform(
            post("/oauth/token")
                .param("client_id", CLIENTID)
                .param("client_secret", CLIENTSECRET)
                .param(OAuth2Utils.GRANT_TYPE, GRANT_TYPE_PASSWORD)
                .param("username", username)
                .param("password", SECRET)
                .param(TokenConstants.REQUEST_TOKEN_FORMAT, OPAQUE.getStringValue())
                .param("response_type", "id_token")
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_FORM_URLENCODED))
            .andExpect(status().isOk())
            .andReturn().getResponse().getContentAsString();
        Map<String, Object> tokenMap = JsonUtils.readValue(content, new TypeReference<Map<String, Object>>() {
        });
        token = (String) tokenMap.get("access_token");
        basic = new String(Base64.encodeBase64((CLIENTID + ":" + CLIENTSECRET).getBytes()));
    }

    @Test
    public void introspectToken_withValidToken() throws Exception {
        getMockMvc().perform(
            post("/introspect")
                .header("Authorization", "Basic " + basic)
                .header(ACCEPT, APPLICATION_JSON_VALUE)
                .header(CONTENT_TYPE, APPLICATION_FORM_URLENCODED_VALUE)
                .param("token", token))
            .andDo(log())
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.active").value("true"))
            .andExpect(jsonPath("$.client_id").value(CLIENTID))
            .andExpect(header().string(CONTENT_TYPE, "application/json;charset=UTF-8"));
    }


    @Test
    public void introspectToken_withInvalidToken() throws Exception {
        getMockMvc().perform(
            post("/introspect")
                .header("Authorization", "Basic " + basic)
                .header(ACCEPT, APPLICATION_JSON_VALUE)
                .header(CONTENT_TYPE, APPLICATION_FORM_URLENCODED_VALUE)
                .param("token", "invalid-token"))
            .andDo(log())
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.active").value("false"))
            .andExpect(header().string(CONTENT_TYPE, "application/json;charset=UTF-8"));
    }

    @Test
    public void check_token_delete() throws Exception {
        getMockMvc().perform(
            delete("/introspect")
                .header("Authorization", "Basic " + basic)
                .header(ACCEPT, APPLICATION_JSON_VALUE)
                .header(CONTENT_TYPE, APPLICATION_FORM_URLENCODED_VALUE)
                .param("token", token))
            .andDo(log())
            .andExpect(status().isMethodNotAllowed())
            .andExpect(jsonPath("$.error").value("method_not_allowed"))
            .andExpect(jsonPath("$.error_description").value(HtmlUtils.htmlEscape("Request method 'DELETE' not supported", "ISO-8859-1")));
    }
}