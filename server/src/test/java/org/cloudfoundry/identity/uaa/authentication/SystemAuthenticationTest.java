/*
 * ****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 * ****************************************************************************
 */

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