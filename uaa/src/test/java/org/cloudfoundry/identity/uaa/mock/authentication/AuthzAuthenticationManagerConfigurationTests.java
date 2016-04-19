/*
 * ******************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * ******************************************************************************
 */

package org.cloudfoundry.identity.uaa.mock.authentication;

import org.cloudfoundry.identity.uaa.authentication.manager.AuthzAuthenticationManager;
import org.cloudfoundry.identity.uaa.authentication.manager.PeriodLockoutPolicy;
import org.cloudfoundry.identity.uaa.test.YamlServletProfileInitializerContextInitializer;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.web.context.support.XmlWebApplicationContext;

import static org.junit.Assert.assertEquals;

public class AuthzAuthenticationManagerConfigurationTests {

    private XmlWebApplicationContext webApplicationContext;
    private MockEnvironment environment;

    @Before
    public void setUp() {
        webApplicationContext = new XmlWebApplicationContext();
        environment = new MockEnvironment();
        webApplicationContext.setEnvironment(environment);
        new YamlServletProfileInitializerContextInitializer().initializeContext(webApplicationContext, "uaa.yml,login.yml");
        webApplicationContext.setConfigLocation("file:./src/main/webapp/WEB-INF/spring-servlet.xml");
    }

    @After
    public void tearDown() throws Exception {
        webApplicationContext.destroy();
        webApplicationContext = null;
        environment = null;
    }

    @Test
    public void testAuthzAuthenticationManagerUsesGlobalLockoutPolicy() throws Exception {
        environment.setProperty("authentication.policy.global.lockoutAfterFailures", "1");
        environment.setProperty("authentication.policy.global.countFailuresWithinSeconds", "2222");
        environment.setProperty("authentication.policy.global.lockoutPeriodSeconds", "152");
        webApplicationContext.refresh();

        AuthzAuthenticationManager manager = (AuthzAuthenticationManager) webApplicationContext.getBean("uaaUserDatabaseAuthenticationManager");
        PeriodLockoutPolicy accountLoginPolicy = (PeriodLockoutPolicy) manager.getAccountLoginPolicy();

        assertEquals(2222, accountLoginPolicy.getLockoutPolicy().getCountFailuresWithin());
        assertEquals(152, accountLoginPolicy.getLockoutPolicy().getLockoutPeriodSeconds());
        assertEquals(1, accountLoginPolicy.getLockoutPolicy().getLockoutAfterFailures());
    }
}
