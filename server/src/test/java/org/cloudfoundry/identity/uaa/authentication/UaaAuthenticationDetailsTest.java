package org.cloudfoundry.identity.uaa.authentication;

import org.junit.Test;

import javax.servlet.http.HttpServletRequest;

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
    public void testLoginHintIsParsed() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getParameter("login_hint")).thenReturn("{\"origin\":\"ldap\"}");

        UaaAuthenticationDetails details = new UaaAuthenticationDetails(request, null);
        assertNotNull(details.getLoginHint());
        assertEquals("ldap", details.getLoginHint().getOrigin());
    }

    @Test
    public void testNoLoginHint() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getParameter("login_hint")).thenReturn(null);

        UaaAuthenticationDetails details = new UaaAuthenticationDetails(request, null);
        assertNull(details.getLoginHint());
    }
}