package org.cloudfoundry.identity.uaa.authentication;

import java.io.IOException;
import java.text.ParseException;
import java.util.Base64;

import javax.servlet.ServletException;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.BadCredentialsException;

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
    public void testBuildValidAuthenticationDetails() throws IOException, ServletException, ParseException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Basic " + new String(Base64.getEncoder().encode("a:".getBytes())));
        UaaAuthenticationDetails details = new UaaAuthenticationDetails(request);
        assertTrue("a".equals(details.getClientId()));
    }

    @Test(expected=BadCredentialsException.class)
    public void testBuildInvalidAuthenticationDetails() throws IOException, ServletException, ParseException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Basic " + new String(Base64.getEncoder().encode(":".getBytes())));
        new UaaAuthenticationDetails(request);
    }
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