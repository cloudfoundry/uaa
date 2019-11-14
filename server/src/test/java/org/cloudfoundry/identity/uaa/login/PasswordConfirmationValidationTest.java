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
package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.account.PasswordConfirmationValidation;
import org.junit.Assert;
import org.junit.Test;

public class PasswordConfirmationValidationTest {

    @Test
    public void testValidWithMatchingPasswords() {
        PasswordConfirmationValidation validation = new PasswordConfirmationValidation("secret", "secret");
        Assert.assertTrue(validation.valid());
    }

    @Test
    public void testInvalidWithMismatchedPasswords() {
        PasswordConfirmationValidation validation = new PasswordConfirmationValidation("secret", "mecret");
        Assert.assertFalse(validation.valid());
    }

    @Test
    public void testInvalidWithEmptyPassword() {
        PasswordConfirmationValidation validation = new PasswordConfirmationValidation("", "");
        Assert.assertFalse(validation.valid());
    }
}
