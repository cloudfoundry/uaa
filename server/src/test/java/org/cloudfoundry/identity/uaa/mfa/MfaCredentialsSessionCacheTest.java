package org.cloudfoundry.identity.uaa.mfa;

import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpSession;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

public class MfaCredentialsSessionCacheTest {

    private MfaCredentialsSessionCache cache;

    @Before
    public void setup() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        ((ServletRequestAttributes)RequestContextHolder.getRequestAttributes()).getRequest().getSession(true);

        cache = new MfaCredentialsSessionCache();
    }

    @Test
    public void testCredentialsAreStoredInSession() {
        UserGoogleMfaCredentials creds = new UserGoogleMfaCredentials("userid", "key", 42, null);

        cache.putCredentials(creds);
        assertEquals(creds, session().getAttribute("SESSION_USER_GOOGLE_MFA_CREDENTIALS"));
    }

    @Test
    public void testReturnsNullWhenNoCredentials() {
        assertNull(cache.getCredentials());
    }

    @Test
    public void testGetCredentials() {
        UserGoogleMfaCredentials creds = new UserGoogleMfaCredentials("userid", "key", 42, null);

        session().setAttribute("SESSION_USER_GOOGLE_MFA_CREDENTIALS", creds);

        assertEquals(creds, cache.getCredentials());
    }

    @Test
    public void testRemoveCredentials() {
        UserGoogleMfaCredentials creds = new UserGoogleMfaCredentials("userid", "key", 42, null);

        session().setAttribute("SESSION_USER_GOOGLE_MFA_CREDENTIALS", creds);

        cache.removeCredentials();

        assertNull(cache.getCredentials());
    }

    @Test
    public void testRemoveTwiceSucceeds() {
        UserGoogleMfaCredentials creds = new UserGoogleMfaCredentials("userid", "key", 42, null);

        session().setAttribute("SESSION_USER_GOOGLE_MFA_CREDENTIALS", creds);

        cache.removeCredentials();
        cache.removeCredentials();
    }

    private HttpSession session() {
        return ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest().getSession(false);
    }
}