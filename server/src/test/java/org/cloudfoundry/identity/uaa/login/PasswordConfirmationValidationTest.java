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
package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.account.PasswordConfirmationValidation;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class PasswordConfirmationValidationTest {

    @Test
    void validWithMatchingPasswords() {
        PasswordConfirmationValidation validation = new PasswordConfirmationValidation("secret", "secret");
        assertThat(validation.valid()).isTrue();
    }

    @Test
    void invalidWithMismatchedPasswords() {
        PasswordConfirmationValidation validation = new PasswordConfirmationValidation("secret", "mecret");
        assertThat(validation.valid()).isFalse();
    }

    @Test
    void invalidWithEmptyPassword() {
        PasswordConfirmationValidation validation = new PasswordConfirmationValidation("", "");
        assertThat(validation.valid()).isFalse();
    }
}
