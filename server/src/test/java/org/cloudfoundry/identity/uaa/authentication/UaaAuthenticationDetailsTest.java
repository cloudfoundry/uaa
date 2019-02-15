package org.cloudfoundry.identity.uaa.authentication;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.BadCredentialsException;

import javax.servlet.http.HttpServletRequest;
import java.util.Base64;

import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class UaaAuthenticationDetailsTest {

    @Test
    public void testToStringDoesNotContainSessionId() {
        UaaAuthenticationDetails details = new UaaAuthenticationDetails(false, "clientid", "origin", "1234");
        String toString = details.toString();
        assertTrue(toString.contains("sessionId=<SESSION>"));
    }

    @Test
    public void testBuildValidAuthenticationDetails() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Basic " + new String(Base64.getEncoder().encode("a:".getBytes())));
        UaaAuthenticationDetails details = new UaaAuthenticationDetails(request);
        assertEquals("a", details.getClientId());
    }

    @Test(expected = BadCredentialsException.class)
    public void testBuildInvalidAuthenticationDetails() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Basic " + new String(Base64.getEncoder().encode(":".getBytes())));
        new UaaAuthenticationDetails(request);
    }

    @Test
    public void testNoLoginHint() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getParameter("login_hint")).thenReturn(null);

        UaaAuthenticationDetails details = new UaaAuthenticationDetails(request, null);
        assertNull(details.getLoginHint());
    }
}