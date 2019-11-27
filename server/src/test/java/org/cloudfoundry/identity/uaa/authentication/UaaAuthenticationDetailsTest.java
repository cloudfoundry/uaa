package org.cloudfoundry.identity.uaa.authentication;

import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.mock.web.MockHttpServletRequest;

import javax.servlet.http.HttpServletRequest;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(PollutionPreventionExtension.class)
class UaaAuthenticationDetailsTest {

    @Test
    void testToStringDoesNotContainSessionId() {
        UaaAuthenticationDetails details = new UaaAuthenticationDetails(false, "clientid", "origin", "1234");
        String toString = details.toString();
        assertTrue(toString.contains("sessionId=<SESSION>"));
    }

    @Test
    void testBuildValidAuthenticationDetails() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setAttribute("clientId", "a");
        UaaAuthenticationDetails details = new UaaAuthenticationDetails(request);
        assertEquals("a", details.getClientId());
    }

    @Test
    void testBuildWithoutAuthenticationDetails() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        UaaAuthenticationDetails details = new UaaAuthenticationDetails(request);
        assertNull(details.getClientId());
    }

    @Test
    void testNoLoginHint() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getParameter("login_hint")).thenReturn(null);

        UaaAuthenticationDetails details = new UaaAuthenticationDetails(request, null);
        assertNull(details.getLoginHint());
    }

    @Test
    void testSavesRequestParameters() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addParameter("key", "value");

        UaaAuthenticationDetails details = new UaaAuthenticationDetails(request, null);
        assertEquals("value", details.getParameterMap().get("key")[0]);
    }

    @Test
    void testDoesNotSaveUsernamePasswordRequestParameters() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        String[] filteredKeys = {"Username", "username", "Password", "password", "Passcode", "passcode"};
        for(String key : filteredKeys) {
            request.addParameter(key, "value");
        }

        UaaAuthenticationDetails details = new UaaAuthenticationDetails(request, null);
        for(String key : filteredKeys) {
            assertNull(details.getParameterMap().get(key));
        }
    }
}