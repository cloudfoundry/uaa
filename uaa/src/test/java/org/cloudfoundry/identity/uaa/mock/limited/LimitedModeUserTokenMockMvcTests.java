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

import org.cloudfoundry.identity.uaa.mock.token.UserTokenMockMvcTests;
import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import java.io.File;

import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.getLimitedModeStatusFile;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.resetLimitedModeStatusFile;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.setLimitedModeStatusFile;

public class LimitedModeUserTokenMockMvcTests extends UserTokenMockMvcTests {
    private File existingStatusFile;
    private File statusFile;

    @Before
    @Override
    public void setUpContext() throws Exception {
        super.setUpContext();
        existingStatusFile = getLimitedModeStatusFile(getWebApplicationContext());
        statusFile = setLimitedModeStatusFile(getWebApplicationContext());
    }


    @After
    public void tearDown() throws Exception {
        resetLimitedModeStatusFile(getWebApplicationContext(), existingStatusFile);
    }

    @Test
    @Ignore("super method uses disabled endpoints")
    @Override
    public void test_create_client_with_user_token_grant() throws Exception {
    }
}
