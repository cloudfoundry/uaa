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

package org.cloudfoundry.identity.uaa.test;


import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.util.StringUtils;

import java.util.Arrays;
import java.util.Collection;

@Ignore("This test is here to simply execute the Flyway create DB script for all databases. Used to aid in writing schema scripts")
@RunWith(Parameterized.class)
public class CreateDB  extends JdbcTestBase {

    private final String profile;

    public CreateDB(String profile) {
        this.profile = profile;
    }

    @Parameters(name = "{index}: profile=[{0}]")
    public static Collection<Object[]> profiles() {
        return Arrays.asList(new Object[][]{
            {"mysql,default"}, {"postgresql,default"}, {""},
        });
    }

    @Override
    public void setUp() throws Exception {
        MockEnvironment environment = new MockEnvironment();
        environment.setActiveProfiles(StringUtils.commaDelimitedListToStringArray(profile));
        setUp(environment);
    }

    @Test
    public void test() {
        System.out.println("DB Created:"+profile);
    }

    @Override
    public void tearDown() throws Exception {
        //no op - no clean up
    }
}
