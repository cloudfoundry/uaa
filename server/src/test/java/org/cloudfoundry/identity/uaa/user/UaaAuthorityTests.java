
package org.cloudfoundry.identity.uaa.user;

import org.junit.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import static org.junit.Assert.*;

/**
 * @author Dave Syer
 *
 */
public class UaaAuthorityTests {

    @Test
    public void testGetAuthority() {
        assertEquals("uaa.user", UaaAuthority.UAA_USER.getAuthority());
    }

    @Test
    public void testValueOf() {
        assertEquals(0, UaaAuthority.UAA_USER.value());
        assertEquals(1, UaaAuthority.UAA_ADMIN.value());
    }

    @Test
    public void testAdminFromAuthorities() {
        assertEquals(UaaAuthority.UAA_ADMIN, UaaAuthority.fromAuthorities("uaa.user,uaa.admin"));
    }

    @Test
    public void testAuthority() {
        assertEquals(UaaAuthority.UAA_ADMIN, UaaAuthority.authority("uaa.admin"));
        assertEquals(UaaAuthority.UAA_USER, UaaAuthority.authority("uaa.user"));
        assertEquals(new SimpleGrantedAuthority("tacos"), UaaAuthority.authority("tacos"));
    }

    @Test
    public void testSubstringAuthority() {
        assertNotEquals(UaaAuthority.UAA_ADMIN, UaaAuthority.authority("some.scope.with.subscope.uaa.admin"));
    }
}
