package org.cloudfoundry.identity.uaa.authentication;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import jakarta.servlet.http.HttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;

class UaaAuthenticationDetailsTest {

    @Test
    void toStringDoesNotContainSessionId() {
        UaaAuthenticationDetails details = new UaaAuthenticationDetails(false, "clientid", "origin", "1234");
        String toString = details.toString();
        assertThat(toString).contains("sessionId=<SESSION>");
    }

    @Test
    void buildValidAuthenticationDetails() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setAttribute("clientId", "a");
        UaaAuthenticationDetails details = new UaaAuthenticationDetails(request);
        assertThat(details.getClientId()).isEqualTo("a");
    }

    @Test
    void buildWithoutAuthenticationDetails() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        UaaAuthenticationDetails details = new UaaAuthenticationDetails(request);
        assertThat(details.getClientId()).isNull();
    }

    @Test
    void noLoginHint() {
        HttpServletRequest request = new MockHttpServletRequest();

        UaaAuthenticationDetails details = new UaaAuthenticationDetails(request, "cliendId");
        assertThat(details.getLoginHint()).isNull();
    }

    @Test
    void publicTokenRequest() {
        HttpServletRequest request = new MockHttpServletRequest("POST", "/oauth/token");

        UaaAuthenticationDetails details = new UaaAuthenticationDetails(request, "cliendId");
        details.setAuthenticationMethod("none");
        assertThat(details.getLoginHint()).isNull();
        assertThat(details.isAuthorizationSet()).isFalse();
        assertThat(details.getRequestPath()).isEqualTo("/oauth/token");
        assertThat(details.getAuthenticationMethod()).isEqualTo("none");
    }

    @Test
    void savesRequestParameters() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addParameter("key", "value");

        UaaAuthenticationDetails details = new UaaAuthenticationDetails(request, null);
        assertThat(details.getParameterMap().get("key")[0]).isEqualTo("value");
    }

    @Test
    void doesNotSaveUsernamePasswordRequestParameters() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        String[] filteredKeys = {"Username", "username", "Password", "password", "Passcode", "passcode"};
        for (String key : filteredKeys) {
            request.addParameter(key, "value");
        }

        UaaAuthenticationDetails details = new UaaAuthenticationDetails(request, null);
        for (String key : filteredKeys) {
            assertThat(details.getParameterMap()).doesNotContainKey(key);
        }
    }
}
