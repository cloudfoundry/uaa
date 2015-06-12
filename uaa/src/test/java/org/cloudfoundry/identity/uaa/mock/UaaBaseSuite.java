/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.mock;

import org.junit.AfterClass;
import org.junit.BeforeClass;

public class UaaBaseSuite {
    private static volatile boolean suiteActive = false;

    /**
     *
     * @return false if the test has been invoked within gradle (based on system property)
     * and the test is not running while the test suite is running.
     */
    public static boolean shouldMockTestBeRun() {
        boolean gradle = Boolean.valueOf(System.getProperty("mock.suite.test"));
        if (gradle) {
            return suiteActive;
        } else {
            return true;
        }
    }

    @BeforeClass
    public static void suiteIsActive() throws Exception {
        suiteActive = true;
    }

    @AfterClass
    public static void suiteIsNotActive() throws Exception {
        suiteActive = false;
    }


}
