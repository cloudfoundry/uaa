package org.cloudfoundry.identity.uaa.mock.config;

import org.cloudfoundry.identity.uaa.config.PasswordPolicy;
import org.cloudfoundry.identity.uaa.test.YamlServletProfileInitializerContextInitializer;
import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.web.context.support.XmlWebApplicationContext;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

/**
 * ****************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 * <p/>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p/>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */
@Ignore
public class PasswordPolicyTests {
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
    public void testReadPasswordProperties() {
        environment.setProperty("password.policy.minLength", "8");
        environment.setProperty("password.policy.maxLength", "100");
        environment.setProperty("password.policy.requireAtLeastOneUpperCaseCharacter", "false");
        environment.setProperty("password.policy.requireAtLeastOneLowerCaseCharacter", "false");
        environment.setProperty("password.policy.requireAtLeastOneDigit", "false");
        environment.setProperty("password.policy.requireAtLeastOneSpecialCharacter", "true");
        webApplicationContext.refresh();
        PasswordPolicy passwordPolicy = webApplicationContext.getBean(PasswordPolicy.class);
        assertThat(passwordPolicy.getMinLength(), is(8));
        assertThat(passwordPolicy.getMaxLength(), is(100));
        assertThat(passwordPolicy.isRequireAtLeastOneUpperCaseCharacter(), is(false));
        assertThat(passwordPolicy.isRequireAtLeastOneLowerCaseCharacter(), is(false));
        assertThat(passwordPolicy.isRequireAtLeastOneDigit(), is(false));
        assertThat(passwordPolicy.isRequireAtLeastOneSpecialCharacter(), is(true));
    }

    @Test
    public void testReadDefaultPasswordProperties() {
        webApplicationContext.refresh();
        PasswordPolicy passwordPolicy = webApplicationContext.getBean(PasswordPolicy.class);
        assertThat(passwordPolicy.getMinLength(), is(6));
        assertThat(passwordPolicy.getMaxLength(), is(128));
        assertThat(passwordPolicy.isRequireAtLeastOneUpperCaseCharacter(), is(true));
        assertThat(passwordPolicy.isRequireAtLeastOneLowerCaseCharacter(), is(true));
        assertThat(passwordPolicy.isRequireAtLeastOneDigit(), is(true));
        assertThat(passwordPolicy.isRequireAtLeastOneSpecialCharacter(), is(false));
    }
}
