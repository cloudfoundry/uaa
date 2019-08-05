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

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.login.LoginMockMvcTests;
import org.cloudfoundry.identity.uaa.web.LimitedModeUaaFilter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;

import static org.cloudfoundry.identity.uaa.web.LimitedModeUaaFilter.DEGRADED;
import static org.junit.Assert.assertTrue;

@ActiveProfiles({ DEGRADED})
class LimitedModeLoginMockMvcTests extends LoginMockMvcTests {


    @BeforeEach
    void setUpLimitedModeLoginMockMvcTests(
            @Autowired LimitedModeUaaFilter limitedModeUaaFilter
    ) {
        assertTrue(isLimitedMode(limitedModeUaaFilter));
    }

    @Nested
    @DefaultTestContext
    @ActiveProfiles({ DEGRADED})
    @TestPropertySource(properties = {"analytics.code=secret_code", "analytics.domain=example.com"})
    class BLoginWithAnalytics extends LoginWithAnalytics{
    }

}
