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

package org.cloudfoundry.identity.uaa.mock.limited;

import org.cloudfoundry.identity.uaa.login.LoginMockMvcTests;
import org.cloudfoundry.identity.uaa.web.LimitedModeUaaFilter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.TestInfo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ActiveProfiles;

import static org.cloudfoundry.identity.uaa.web.LimitedModeUaaFilter.DEGRADED;
import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

@ActiveProfiles(DEGRADED)
class LimitedModeLoginMockMvcTests extends LoginMockMvcTests {

    @BeforeEach
    void setUpLimitedModeLoginMockMvcTests(
            TestInfo testInfo,
            @Autowired LimitedModeUaaFilter limitedModeUaaFilter
    ) {
        assumeTestClassIsOuterClass(testInfo);
        assertTrue(limitedModeUaaFilter.isEnabled());
    }

    private void assumeTestClassIsOuterClass(TestInfo testInfo) {
        assumeTrue(testInfo.getTestClass().orElseThrow(AssertionError::new).isAssignableFrom(this.getClass()),
                "To run in degraded mode, we need to set active profiles to 'degraded'. " +
                        "The active profiles of a nested class may be set independently of its outer class. " +
                        "Hence such a nested class will run identically when run from it's outer class' subclass. " +
                        "It is therefore redundant to run such a nested class in both parent and subclass."
        );
    }
}
