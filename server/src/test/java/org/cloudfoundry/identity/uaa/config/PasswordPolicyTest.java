package org.cloudfoundry.identity.uaa.config;

import org.cloudfoundry.identity.uaa.provider.PasswordPolicy;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/*******************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 * <p/>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p/>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
class PasswordPolicyTest {
    @Test
    void allPresentAndPositive_makesSureNothingUnset() {
        PasswordPolicy passwordPolicy = new PasswordPolicy();
        assertThat(passwordPolicy.allPresentAndPositive()).isFalse();
        assertThat(passwordPolicy.setMinLength(1).allPresentAndPositive()).isFalse();
        assertThat(passwordPolicy.setMaxLength(22).allPresentAndPositive()).isFalse();
        assertThat(passwordPolicy.setRequireUpperCaseCharacter(0).allPresentAndPositive()).isFalse();
        assertThat(passwordPolicy.setRequireLowerCaseCharacter(1).allPresentAndPositive()).isFalse();
        assertThat(passwordPolicy.setRequireDigit(0).allPresentAndPositive()).isFalse();
        assertThat(passwordPolicy.setRequireSpecialCharacter(2).allPresentAndPositive()).isFalse();
        assertThat(passwordPolicy.setExpirePasswordInMonths(23).allPresentAndPositive()).isTrue();
    }
}
