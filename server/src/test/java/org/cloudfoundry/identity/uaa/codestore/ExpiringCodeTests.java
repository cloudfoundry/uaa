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
package org.cloudfoundry.identity.uaa.codestore;

import org.junit.jupiter.api.Test;

import java.sql.Timestamp;

import static org.assertj.core.api.Assertions.assertThat;

class ExpiringCodeTests {
    @Test
    void isExpired() {
        ExpiringCode expiringCode = new ExpiringCode();
        assertThat(expiringCode.isExpired()).isFalse();

        expiringCode.setExpiresAt(new Timestamp(System.currentTimeMillis() - 1000));
        assertThat(expiringCode.isExpired()).isTrue();

        expiringCode.setExpiresAt(new Timestamp(System.currentTimeMillis() + 1000));
        assertThat(expiringCode.isExpired()).isFalse();
    }
}
