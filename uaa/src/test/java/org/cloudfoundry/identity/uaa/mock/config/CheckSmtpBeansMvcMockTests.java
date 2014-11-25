/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.mock.config;

import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.Collection;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import com.googlecode.flyway.core.Flyway;
import org.cloudfoundry.identity.uaa.login.EmailService;
import org.cloudfoundry.identity.uaa.login.util.FakeJavaMailSender;
import org.cloudfoundry.identity.uaa.test.YamlServletProfileInitializerContextInitializer;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.util.ReflectionUtils;
import org.springframework.web.context.support.XmlWebApplicationContext;
@RunWith(Parameterized.class)
public class CheckSmtpBeansMvcMockTests {

    @Parameterized.Parameters
    public static Collection parameters() {
        return Arrays.asList(new String[] {""}, new String[] {"localhost"});
    }

    XmlWebApplicationContext webApplicationContext;
    private String smtpHost;

    public CheckSmtpBeansMvcMockTests(String smtpHost) {
        this.smtpHost = smtpHost;
    }

    @Before
    public void setUp() {
        MockEnvironment mockEnvironment = new MockEnvironment();
        mockEnvironment.setProperty("smtp.host", smtpHost);
        webApplicationContext = new XmlWebApplicationContext();
        webApplicationContext.setEnvironment(mockEnvironment);
        new YamlServletProfileInitializerContextInitializer().initializeContext(webApplicationContext, "uaa.yml,login.yml");
        webApplicationContext.setConfigLocation("file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        webApplicationContext.refresh();
    }


    @Test
    public void testJavaMailSender() throws Exception {
        EmailService emailService = webApplicationContext.getBean("emailService", EmailService.class);
        Field f = ReflectionUtils.findField(EmailService.class, "mailSender");
        assertNotNull("Unable to find the JavaMailSender object on EmailService for validation.", f);
        String smtpHost = webApplicationContext.getEnvironment().getProperty("smtp.host");
        if (smtpHost==null || smtpHost.length()==0) {
            checkSender(f, emailService, FakeJavaMailSender.class);
        } else {
            checkSender(f, emailService, JavaMailSenderImpl.class);
        }


    }

    protected void checkSender(Field f, EmailService service, Class<?> clazz) throws Exception {
        boolean accessible = f.isAccessible();
        f.setAccessible(true);
        assertEquals(clazz, f.get(service).getClass());
        f.setAccessible(accessible);
    }

    @After
    public void tearDown() throws Exception{
        Flyway flyway = webApplicationContext.getBean(Flyway.class);
        flyway.clean();
        webApplicationContext.destroy();
    }


}
