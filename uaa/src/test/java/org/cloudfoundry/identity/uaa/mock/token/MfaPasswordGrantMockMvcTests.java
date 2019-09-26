package org.cloudfoundry.identity.uaa.mock.token;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.cloudfoundry.identity.uaa.authentication.event.AbstractUaaAuthenticationEvent;
import org.cloudfoundry.identity.uaa.authentication.event.MfaAuthenticationFailureEvent;
import org.cloudfoundry.identity.uaa.authentication.event.MfaAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.mfa.StatelessMfaAuthenticationFilter;
import org.cloudfoundry.identity.uaa.test.TestApplicationEventListener;
import org.cloudfoundry.identity.uaa.user.UaaUser;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.context.support.GenericWebApplicationContext;

import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.getMfaCodeFromCredentials;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.removeEventListener;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.REQUEST_TOKEN_FORMAT;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.TokenFormat.OPAQUE;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class MfaPasswordGrantMockMvcTests extends AbstractTokenMockMvcTests {
    private TestApplicationEventListener<AbstractUaaAuthenticationEvent> listener;

    @Autowired
    private StatelessMfaAuthenticationFilter statelessMfaAuthenticationFilter;

    @BeforeEach
    public void setupForMfaPasswordGrant() throws Exception {
        super.setupForMfaPasswordGrant();
        listener = TestApplicationEventListener.forEventClass(AbstractUaaAuthenticationEvent.class);
        ((GenericWebApplicationContext) webApplicationContext).addApplicationListener(listener);
    }

    @AfterEach
    void clearListeners() {
        if (listener!=null) {
            removeEventListener(webApplicationContext, listener);
            listener.clearEvents();
        }
    }

    @Test
    void filter_only_triggers_on_password_grant() {
        assertThat(statelessMfaAuthenticationFilter.getSupportedGrantTypes(), containsInAnyOrder("password"));
    }

    @Test
    void mfa_happy_path() throws Exception {
        listener.clearEvents();
        mockMvc.perform(
            post("/oauth/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .param(OAuth2Utils.GRANT_TYPE, "password")
                .param(OAuth2Utils.CLIENT_ID, "cf")
                .param(REQUEST_TOKEN_FORMAT, OPAQUE.getStringValue())
                .param("client_secret", "")
                .param("username", "marissa")
                .param("password", "koala")
                .param("mfaCode", String.valueOf(getMfaCodeFromCredentials(credentials)))
        )
            .andDo(print())
            .andExpect(status().isOk());


        validateAuthEvents(
                Collections.singletonList(
                        MfaAuthenticationSuccessEvent.class
                ), "marissa"
        );
    }

    private void validateAuthEvents(List<Class<? extends AbstractUaaAuthenticationEvent>> eventsExpected, String username) {
        List<AbstractUaaAuthenticationEvent> events = new ArrayList(listener.getEvents());
        for (Class<? extends AbstractUaaAuthenticationEvent> clazz : eventsExpected) {
            for (AbstractUaaAuthenticationEvent auth : events) {
                if (auth.getClass().equals(clazz)) {
                    UaaUser user = getUaaUser(auth);
                    assertEquals(username, user.getUsername());
                }
            }
            assertTrue(events.removeIf(e -> e.getClass().equals(clazz)));
        }
    }

    private UaaUser getUaaUser(AbstractUaaAuthenticationEvent auth) {
        return (UaaUser)ReflectionTestUtils.getField(auth, "user");
    }

    @Test
    void invalid_code() throws Exception {
        mockMvc.perform(
            post("/oauth/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .param(OAuth2Utils.GRANT_TYPE, "password")
                .param(OAuth2Utils.CLIENT_ID, "cf")
                .param(REQUEST_TOKEN_FORMAT, OPAQUE.getStringValue())
                .param("client_secret", "")
                .param("username", "marissa")
                .param("password", "koala")
                .param("mfaCode", "1234")
        )
            .andDo(print())
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("error").value("unauthorized"))
            .andExpect(jsonPath("error_description").value(containsString("Bad credentials")));
        validateAuthEvents(
                Collections.singletonList(
                        MfaAuthenticationFailureEvent.class
                ), "marissa"
        );
    }

    @Test
    void not_registered() throws Exception {
        deleteMfaRegistrations();
        mockMvc.perform(
            post("/oauth/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .param(OAuth2Utils.GRANT_TYPE, "password")
                .param(OAuth2Utils.CLIENT_ID, "cf")
                .param(REQUEST_TOKEN_FORMAT, OPAQUE.getStringValue())
                .param("client_secret", "")
                .param("username", "marissa")
                .param("password", "koala")
                .param("mfaCode", "1234")
        )
            .andDo(print())
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("error").value("invalid_request"))
            .andExpect(jsonPath("error_description").value(containsString("register a multi-factor")));
        validateAuthEvents(
                Collections.singletonList(
                        MfaAuthenticationFailureEvent.class
                ), "marissa"
        );
    }
}
