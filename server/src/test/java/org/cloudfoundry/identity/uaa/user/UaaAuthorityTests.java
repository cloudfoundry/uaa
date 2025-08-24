/*
 * *****************************************************************************
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

import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Dave Syer
 */
class UaaAuthorityTests {

    @Test
    void getAuthority() {
        assertThat(UaaAuthority.UAA_USER.getAuthority()).isEqualTo("uaa.user");
    }

    @Test
    void valueOf() {
        assertThat(UaaAuthority.UAA_USER.value()).isZero();
        assertThat(UaaAuthority.UAA_ADMIN.value()).isOne();
    }

    @Test
    void adminFromAuthorities() {
        assertThat(UaaAuthority.fromAuthorities("uaa.user,uaa.admin")).isEqualTo(UaaAuthority.UAA_ADMIN);
    }

    @Test
    void authority() {
        assertThat(UaaAuthority.authority("uaa.admin")).isEqualTo(UaaAuthority.UAA_ADMIN);
        assertThat(UaaAuthority.authority("uaa.user")).isEqualTo(UaaAuthority.UAA_USER);
        assertThat(UaaAuthority.authority("tacos")).isEqualTo(new SimpleGrantedAuthority("tacos"));
    }

    @Test
    void substringAuthority() {
        assertThat(UaaAuthority.authority("some.scope.with.subscope.uaa.admin")).isNotEqualTo(UaaAuthority.UAA_ADMIN);
    }
}
