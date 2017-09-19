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

package org.cloudfoundry.identity.uaa.mock.degraded;

import org.cloudfoundry.identity.uaa.login.LoginMockMvcTests;
import org.cloudfoundry.identity.uaa.web.DegradedModeUaaFilter;
import org.junit.After;
import org.junit.Before;

public class DegradedModeLoginMockMvcTests extends LoginMockMvcTests {

    private boolean original;

    @Before
    @Override
    public void setUpContext() throws Exception {
        super.setUpContext();
        DegradedModeUaaFilter bean = getWebApplicationContext().getBean(DegradedModeUaaFilter.class);
        original = bean.isEnabled();
        bean.setEnabled(true);
    }


    @After
    @Override
    public void tearDown() throws Exception {
        super.tearDown();
        getWebApplicationContext().getBean(DegradedModeUaaFilter.class).setEnabled(original);
    }

}
