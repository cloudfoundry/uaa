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

import org.cloudfoundry.identity.uaa.authentication.manager.AuthzAuthenticationManager;
import org.cloudfoundry.identity.uaa.authentication.manager.ChainedAuthenticationManager;
import org.cloudfoundry.identity.uaa.config.YamlServletProfileInitializer;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.mock.web.MockServletContext;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.web.context.support.XmlWebApplicationContext;

import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertEquals;

public class AuthzAuthenticationManagerVerificationMockMvcTests {

    private XmlWebApplicationContext webApplicationContext;

    @Before
    public void setUp() {
        webApplicationContext = new XmlWebApplicationContext();
        webApplicationContext.setServletContext(new MockServletContext());
        webApplicationContext.setConfigLocation("file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        new YamlServletProfileInitializer().initialize(webApplicationContext);
        webApplicationContext.refresh();
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
        String[] profiles = webApplicationContext.getEnvironment().getActiveProfiles();
        List<String> plist = Arrays.asList(profiles);
        if (plist.contains("ldap") || plist.contains("keystone")) {
            assertEquals(ChainedAuthenticationManager.class, webApplicationContext.getBean("authzAuthenticationMgr").getClass());
        } else {
            assertEquals(AuthzAuthenticationManager.class, webApplicationContext.getBean("authzAuthenticationMgr").getClass());
        }
    }
}
