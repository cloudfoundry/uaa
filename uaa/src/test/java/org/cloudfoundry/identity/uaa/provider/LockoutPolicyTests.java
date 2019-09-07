/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.provider;

import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class LockoutPolicyTests {

    @Test
    public void allPresentAndPositive_makesSureNothingUnset() {
        LockoutPolicy lockoutPolicy = new LockoutPolicy();
        assertFalse(lockoutPolicy.allPresentAndPositive());
        assertFalse(lockoutPolicy.setCountFailuresWithin(1).allPresentAndPositive());
        assertFalse(lockoutPolicy.setLockoutAfterFailures(10).allPresentAndPositive());
        assertTrue(lockoutPolicy.setLockoutPeriodSeconds(20).allPresentAndPositive());
    }
}
