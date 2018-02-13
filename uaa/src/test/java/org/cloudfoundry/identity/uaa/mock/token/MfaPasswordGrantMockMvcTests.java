package org.cloudfoundry.identity.uaa.mock.token;

import org.cloudfoundry.identity.uaa.mfa.StatelessMfaAuthenticationFilter;

import org.junit.Before;
import org.junit.Test;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.common.util.OAuth2Utils;

import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.getMfaCodeFromCredentials;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.OPAQUE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.REQUEST_TOKEN_FORMAT;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class MfaPasswordGrantMockMvcTests extends AbstractTokenMockMvcTests {

    @Before
    public void setupForMfaPasswordGrant() throws Exception {
        super.setupForMfaPasswordGrant();
    }

    @Test
    public void filter_only_triggers_on_password_grant() throws Exception {
        StatelessMfaAuthenticationFilter filter = getWebApplicationContext().getBean(StatelessMfaAuthenticationFilter.class);
        assertThat(filter.getSupportedGrantTypes(), containsInAnyOrder("password"));
    }

    @Test
    public void mfa_happy_path() throws Exception {
        getMockMvc().perform(
            post("/oauth/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .param(OAuth2Utils.RESPONSE_TYPE, "token")
                .param(OAuth2Utils.GRANT_TYPE, "password")
                .param(OAuth2Utils.CLIENT_ID, "cf")
                .param(REQUEST_TOKEN_FORMAT, OPAQUE)
                .param("client_secret", "")
                .param("username", "marissa")
                .param("password", "koala")
                .param("mfaCode", String.valueOf(getMfaCodeFromCredentials(credentials)))
        )
            .andDo(print())
            .andExpect(status().isOk());
    }

    @Test
    public void invalid_code() throws Exception {
        getMockMvc().perform(
            post("/oauth/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .param(OAuth2Utils.RESPONSE_TYPE, "token")
                .param(OAuth2Utils.GRANT_TYPE, "password")
                .param(OAuth2Utils.CLIENT_ID, "cf")
                .param(REQUEST_TOKEN_FORMAT, OPAQUE)
                .param("client_secret", "")
                .param("username", "marissa")
                .param("password", "koala")
                .param("mfaCode", "1234")
        )
            .andDo(print())
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("error").value("unauthorized"))
            .andExpect(jsonPath("error_description").value(containsString("Bad credentials")));
    }

    @Test
    public void not_registered() throws Exception {
        deleteMfaRegistrations();
        getMockMvc().perform(
            post("/oauth/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .param(OAuth2Utils.RESPONSE_TYPE, "token")
                .param(OAuth2Utils.GRANT_TYPE, "password")
                .param(OAuth2Utils.CLIENT_ID, "cf")
                .param(REQUEST_TOKEN_FORMAT, OPAQUE)
                .param("client_secret", "")
                .param("username", "marissa")
                .param("password", "koala")
                .param("mfaCode", "1234")
        )
            .andDo(print())
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("error").value("invalid_request"))
            .andExpect(jsonPath("error_description").value(containsString("register a multi-factor")));
    }



}
