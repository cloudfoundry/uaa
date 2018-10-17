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

import org.cloudfoundry.identity.uaa.TestSpringContext;
import org.cloudfoundry.identity.uaa.login.LoginMockMvcTests;
import org.junit.After;
import org.junit.Before;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.web.context.WebApplicationContext;

import java.io.File;

import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.getLimitedModeStatusFile;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.resetLimitedModeStatusFile;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.setLimitedModeStatusFile;

@RunWith(SpringJUnit4ClassRunner.class)
@ActiveProfiles("default")
@WebAppConfiguration
@ContextConfiguration(classes = TestSpringContext.class)
public class LimitedModeLoginMockMvcTests extends LoginMockMvcTests {
    @Autowired
    private WebApplicationContext webApplicationContext;

    private File statusFile;
    private File existingStatusFile = null;

    @Before
    @Override
    public void setUpContext() throws Exception {
        super.setUpContext();
        existingStatusFile = getLimitedModeStatusFile(webApplicationContext);
        statusFile = setLimitedModeStatusFile(webApplicationContext);
    }

    @After
    @Override
    public void tearDown() throws Exception {
        super.tearDown();
        resetLimitedModeStatusFile(webApplicationContext, existingStatusFile);
    }

}
