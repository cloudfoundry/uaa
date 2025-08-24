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

import org.junit.jupiter.api.Test;

import static java.util.Collections.emptyList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.authentication.SystemAuthentication.PRINCIPAL;

class SystemAuthenticationTest {

    private final SystemAuthentication auth = SystemAuthentication.SYSTEM_AUTHENTICATION;

    @Test
    void getAuthorities() {
        assertThat(auth.getAuthorities()).isSameAs(emptyList());
    }

    @Test
    void getCredentials() {
        assertThat(auth.getCredentials()).isNull();
    }

    @Test
    void getDetails() {
        assertThat(auth.getDetails()).isEqualTo(PRINCIPAL);
    }

    @Test
    void getPrincipal() {
        assertThat(auth.getPrincipal()).isEqualTo(PRINCIPAL);
    }

    @Test
    void isAuthenticated() {
        assertThat(auth.isAuthenticated()).isTrue();
    }

    @Test
    void setAuthenticated() {
        auth.setAuthenticated(false);
        isAuthenticated();
    }

    @Test
    void getName() {
        assertThat(auth.getName()).isEqualTo(PRINCIPAL);
    }

}