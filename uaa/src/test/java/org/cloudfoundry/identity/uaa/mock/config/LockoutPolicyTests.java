package org.cloudfoundry.identity.uaa.mock.config;

import org.cloudfoundry.identity.uaa.provider.LockoutPolicy;
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
