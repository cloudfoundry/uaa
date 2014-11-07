/*******************************************************************************
 *     Cloud Foundry 
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
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

import org.junit.Assert;
import org.junit.Test;

public class ChangePasswordValidationTest {

    @Test
    public void testValidWithMatchingPasswords() throws Exception {
        ChangePasswordValidation validation = new ChangePasswordValidation("secret", "secret");
        Assert.assertTrue(validation.valid());
    }

    @Test
    public void testInvalidWithMismatchedPasswords() throws Exception {
        ChangePasswordValidation validation = new ChangePasswordValidation("secret", "mecret");
        Assert.assertFalse(validation.valid());
    }

    @Test
    public void testInvalidWithEmptyPassword() throws Exception {
        ChangePasswordValidation validation = new ChangePasswordValidation("", "");
        Assert.assertFalse(validation.valid());
    }
}
