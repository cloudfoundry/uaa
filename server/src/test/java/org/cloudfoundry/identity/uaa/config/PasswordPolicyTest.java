package org.cloudfoundry.identity.uaa.config;

import org.cloudfoundry.identity.uaa.provider.PasswordPolicy;
import org.junit.Test;

import static org.junit.Assert.*;

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
public class PasswordPolicyTest {
    @Test
    public void allPresentAndPositive_makesSureNothingUnset() {
        PasswordPolicy passwordPolicy = new PasswordPolicy();
        assertFalse(passwordPolicy.allPresentAndPositive());
        assertFalse(passwordPolicy.setMinLength(1).allPresentAndPositive());
        assertFalse(passwordPolicy.setMaxLength(22).allPresentAndPositive());
        assertFalse(passwordPolicy.setRequireUpperCaseCharacter(0).allPresentAndPositive());
        assertFalse(passwordPolicy.setRequireLowerCaseCharacter(1).allPresentAndPositive());
        assertFalse(passwordPolicy.setRequireDigit(0).allPresentAndPositive());
        assertFalse(passwordPolicy.setRequireSpecialCharacter(2).allPresentAndPositive());
        assertTrue(passwordPolicy.setExpirePasswordInMonths(23).allPresentAndPositive());
    }
}
