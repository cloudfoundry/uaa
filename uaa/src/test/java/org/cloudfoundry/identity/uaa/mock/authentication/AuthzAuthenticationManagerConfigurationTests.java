/*
 * ******************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
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

import java.util.Arrays;
import java.util.List;

import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import org.cloudfoundry.identity.uaa.authentication.manager.AuthzAuthenticationManager;
import org.cloudfoundry.identity.uaa.authentication.manager.ChainedAuthenticationManager;
import org.cloudfoundry.identity.uaa.authentication.manager.CheckIdpEnabledAuthenticationManager;
import org.cloudfoundry.identity.uaa.authentication.manager.PeriodLockoutPolicy;
import org.cloudfoundry.identity.uaa.test.YamlServletProfileInitializerContextInitializer;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.web.context.support.XmlWebApplicationContext;

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
    /**
     * We have a condition in the AutzhAuthenticationManager that automatically
     * fails a password validation for zero length password.
     * This test prevents that the authzAuthenticationMgr gets swapped out without
     * the developer being notified.
     * @throws Exception
     */
    @Test
    public void verifyAuthzAuthenticationManagerClassInStandardProfile() throws Exception {
        webApplicationContext.refresh();
        String[] profiles = webApplicationContext.getEnvironment().getActiveProfiles();
        List<String> plist = Arrays.asList(profiles);
        if (plist.contains("ldap") || plist.contains("keystone")) {
            assertEquals(ChainedAuthenticationManager.class, webApplicationContext.getBean("authzAuthenticationMgr").getClass());
        } else {
            assertEquals(CheckIdpEnabledAuthenticationManager.class, webApplicationContext.getBean("authzAuthenticationMgr").getClass());
        }
    }

    @Test
    public void testAuthenticationPolicyDefaults() throws Exception {
        webApplicationContext.refresh();
        PeriodLockoutPolicy periodLockoutPolicy = webApplicationContext.getBean(PeriodLockoutPolicy.class);
        assertThat(periodLockoutPolicy.getLockoutAfterFailures(), equalTo(5));
        assertThat(periodLockoutPolicy.getCountFailuresWithin(), equalTo(3600));
        assertThat(periodLockoutPolicy.getLockoutPeriodSeconds(), equalTo(300));
    }

    @Test
    public void testAuthenticationPolicyConfig() throws Exception {
        environment.setProperty("authentication.policy.lockoutAfterFailures", "10");
        environment.setProperty("authentication.policy.countFailuresWithinSeconds", "7200");
        environment.setProperty("authentication.policy.lockoutPeriodSeconds", "600");
        webApplicationContext.refresh();
        PeriodLockoutPolicy periodLockoutPolicy = webApplicationContext.getBean(PeriodLockoutPolicy.class);
        assertThat(periodLockoutPolicy.getLockoutAfterFailures(), equalTo(10));
        assertThat(periodLockoutPolicy.getCountFailuresWithin(), equalTo(7200));
        assertThat(periodLockoutPolicy.getLockoutPeriodSeconds(), equalTo(600));
    }
}
