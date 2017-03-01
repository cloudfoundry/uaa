/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.oauth;

import org.cloudfoundry.identity.uaa.client.UaaScopes;
import org.junit.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class UaaScopesTests {

    private UaaScopes uaaScopes = new UaaScopes();

    @Test
    public void testGetUaaScopes() throws Exception {
        assertEquals(26, uaaScopes.getUaaScopes().size());
        assertEquals(26, uaaScopes.getUaaAuthorities().size());
    }

    @Test
    public void testGetUaaAuthorities() throws Exception {
        List<GrantedAuthority> authorities = uaaScopes.getUaaAuthorities();
        List<GrantedAuthority> expected = getGrantedAuthorities();
        assertEquals(expected, authorities);
    }

    protected List<GrantedAuthority> getGrantedAuthorities() {
        List<GrantedAuthority> expected = new LinkedList<>();
        for (String s : uaaScopes.getUaaScopes()) {
            expected.add(new SimpleGrantedAuthority(s));
        }
        return expected;
    }

    @Test
    public void testIsWildcardScope() throws Exception {
        for (String s : uaaScopes.getUaaScopes()) {
            if (s.contains("*")) {
                assertTrue(uaaScopes.isWildcardScope(s));
                assertTrue(uaaScopes.isWildcardScope(new SimpleGrantedAuthority(s)));
            } else {
                assertFalse(uaaScopes.isWildcardScope(s));
                assertFalse(uaaScopes.isWildcardScope(new SimpleGrantedAuthority(s)));
            }
        }
    }

    @Test
    public void testIsUaaScope() throws Exception {
        for (String scope : uaaScopes.getUaaScopes()) {
            assertTrue(uaaScopes.isUaaScope(scope));
        }

        for (GrantedAuthority scope : uaaScopes.getUaaAuthorities()) {
            assertTrue(uaaScopes.isUaaScope(scope));
        }

        for (GrantedAuthority scope : getGrantedAuthorities()) {
            assertTrue(uaaScopes.isUaaScope(scope));
        }
    }

    @Test
    public void test_mandatory_scopes_valid() throws Exception {
        List<String> mandatoryScopes = Arrays.asList("scope1","scope2","scope3");
        List<String> requestedScopes = Arrays.asList("scope1","scope2","scope3","scope4");
        assertTrue(uaaScopes.hasMandatoryScopes(mandatoryScopes, requestedScopes));
    }

    @Test
    public void test_mandatory_scopes_invalid() throws Exception {
        List<String> mandatoryScopes = Arrays.asList("scope1","scope2","scope3", "scope5");
        List<String> requestedScopes = Arrays.asList("scope1","scope2","scope3","scope4");
        assertFalse(uaaScopes.hasMandatoryScopes(mandatoryScopes, requestedScopes));
    }


    @Test(expected = NullPointerException.class)
    public void test_mandatory_scopes_npe_arg1() throws Exception {
        List<String> oneSet = Arrays.asList("scope1","scope2","scope3", "scope5");
        uaaScopes.hasMandatoryScopes(null, oneSet);
    }

    @Test(expected = NullPointerException.class)
    public void test_mandatory_scopes_npe_arg2() throws Exception {
        List<String> oneSet = Arrays.asList("scope1","scope2","scope3", "scope5");
        uaaScopes.hasMandatoryScopes(oneSet, null);
    }
}
