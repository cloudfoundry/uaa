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
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.LinkedList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class UaaScopesTests {

    private final UaaScopes uaaScopes = new UaaScopes();

    @Test
    void getUaaScopes() {
        assertThat(uaaScopes.getUaaScopes()).hasSize(31);
        assertThat(uaaScopes.getUaaAuthorities()).hasSize(31);
    }

    @Test
    void getUaaAuthorities() {
        List<GrantedAuthority> authorities = uaaScopes.getUaaAuthorities();
        List<GrantedAuthority> expected = getGrantedAuthorities();
        assertThat(authorities).isEqualTo(expected);
    }

    protected List<GrantedAuthority> getGrantedAuthorities() {
        List<GrantedAuthority> expected = new LinkedList<>();
        for (String s : uaaScopes.getUaaScopes()) {
            expected.add(new SimpleGrantedAuthority(s));
        }
        return expected;
    }

    @Test
    void isWildcardScope() {
        for (String s : uaaScopes.getUaaScopes()) {
            if (s.contains("*")) {
                assertThat(uaaScopes.isWildcardScope(s)).isTrue();
                assertThat(uaaScopes.isWildcardScope(new SimpleGrantedAuthority(s))).isTrue();
            } else {
                assertThat(uaaScopes.isWildcardScope(s)).isFalse();
                assertThat(uaaScopes.isWildcardScope(new SimpleGrantedAuthority(s))).isFalse();
            }
        }
    }

    @Test
    void isUaaScope() {
        for (String scope : uaaScopes.getUaaScopes()) {
            assertThat(uaaScopes.isUaaScope(scope)).isTrue();
        }

        for (GrantedAuthority scope : uaaScopes.getUaaAuthorities()) {
            assertThat(uaaScopes.isUaaScope(scope)).isTrue();
        }

        for (GrantedAuthority scope : getGrantedAuthorities()) {
            assertThat(uaaScopes.isUaaScope(scope)).isTrue();
        }
    }
}
