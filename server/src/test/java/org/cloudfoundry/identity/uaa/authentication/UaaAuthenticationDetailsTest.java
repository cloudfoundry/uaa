package org.cloudfoundry.identity.uaa.authentication;

import org.cloudfoundry.identity.uaa.security.PollutionPreventionExtension;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.BadCredentialsException;

import javax.servlet.http.HttpServletRequest;
import java.util.Base64;

import static org.junit.Assert.*;
import static org.junit.jupiter.api.Assertions.assertThrows;
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

    private static String buildHttpBasic(String username, String password) {
        return "Basic " + new String(Base64.getEncoder().encode((username + ":" + password).getBytes()));
    }

    @Test
    void testBuildValidAuthenticationDetails() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", buildHttpBasic("a", "does not matter"));
        UaaAuthenticationDetails details = new UaaAuthenticationDetails(request);
        assertEquals("a", details.getClientId());
    }

    @Test
    void testBuildInvalidAuthenticationDetails() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", buildHttpBasic("", ""));
        assertThrows(BadCredentialsException.class, () -> new UaaAuthenticationDetails(request));
    }

    @Test
    void testNoLoginHint() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getParameter("login_hint")).thenReturn(null);

        UaaAuthenticationDetails details = new UaaAuthenticationDetails(request, null);
        assertNull(details.getLoginHint());
    }
}