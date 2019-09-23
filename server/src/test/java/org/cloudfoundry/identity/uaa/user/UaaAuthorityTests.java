/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
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
