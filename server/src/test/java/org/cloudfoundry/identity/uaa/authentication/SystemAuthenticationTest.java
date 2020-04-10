package org.cloudfoundry.identity.uaa.authentication;

import org.junit.Test;

import static java.util.Collections.emptyList;
import static org.cloudfoundry.identity.uaa.authentication.SystemAuthentication.PRINCIPAL;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

public class SystemAuthenticationTest {

    private SystemAuthentication auth = SystemAuthentication.SYSTEM_AUTHENTICATION;

    @Test
    public void getAuthorities() {
        assertSame(emptyList(), auth.getAuthorities());
    }

    @Test
    public void getCredentials() {
        assertNull(auth.getCredentials());
    }

    @Test
    public void getDetails() {
        assertEquals(PRINCIPAL, auth.getDetails());
    }

    @Test
    public void getPrincipal() {
        assertEquals(PRINCIPAL, auth.getPrincipal());
    }

    @Test
    public void isAuthenticated() {
        assertTrue(auth.isAuthenticated());
    }

    @Test
    public void setAuthenticated() {
        auth.setAuthenticated(false);
        isAuthenticated();
    }

    @Test
    public void getName() {
        assertEquals(PRINCIPAL, auth.getName());
    }

}