/*******************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 * <p>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.login;

import com.dumbster.smtp.SimpleSmtpServer;
import com.dumbster.smtp.SmtpMessage;
import org.cloudfoundry.identity.uaa.login.test.MockMvcTestClient;
import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.util.SetServerNameRequestPostProcessor;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import java.util.Iterator;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.securityContext;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class InvitationsControllerMockMvcTests extends InjectedMockContextTest {
    private static SimpleSmtpServer mailServer;
    private MockMvcTestClient mockMvcTestClient;
    private MockMvcUtils mockMvcUtils;
    private JavaMailSender originalSender;
    private RandomValueStringGenerator generator = new RandomValueStringGenerator();

    @BeforeClass
    public static void startMailServer() throws Exception {
        mailServer = SimpleSmtpServer.start(2525);
    }

    @Before
    public void setUp() throws Exception {
        originalSender = getWebApplicationContext().getBean("emailService", EmailService.class).getMailSender();

        JavaMailSenderImpl mailSender = new JavaMailSenderImpl();
        mailSender.setHost("localhost");
        mailSender.setPort(2525);
        getWebApplicationContext().getBean("emailService", EmailService.class).setMailSender(mailSender);

        Assert.assertNotNull(getWebApplicationContext().getBean("messageService"));

        mockMvcTestClient = new MockMvcTestClient(getMockMvc());

        for (Iterator i = mailServer.getReceivedEmail(); i.hasNext();) {
            i.next();
            i.remove();
        }
        mockMvcUtils = MockMvcUtils.utils();
    }

    @After
    public void restoreMailSender() {
        ((MockEnvironment) getWebApplicationContext().getEnvironment()).setProperty("assetBaseUrl", "/resources/oss");
        ((MockEnvironment) getWebApplicationContext().getEnvironment()).setProperty("login.brand", "oss");
        getWebApplicationContext().getBean("emailService", EmailService.class).setMailSender(originalSender);
    }

    @AfterClass
    public static void stopMailServer() throws Exception {
        if (mailServer!=null) {
            mailServer.stop();
        }
    }


    @Test
    public void testAcceptInvitationEmailWithOssBrand() throws Exception {
        ((MockEnvironment) getWebApplicationContext().getEnvironment()).setProperty("login.brand", "oss");

        getMockMvc().perform(get(getAcceptInvitationLink()))
                .andExpect(content().string(containsString("Create your account")))
                .andExpect(content().string(not(containsString("Pivotal ID"))))
                .andExpect(content().string(not(containsString("Create Pivotal ID"))))
                .andExpect(content().string(containsString("Create account")));
    }

    @Test
    public void testAcceptInvitationEmailWithPivotalBrand() throws Exception {
        ((MockEnvironment) getWebApplicationContext().getEnvironment()).setProperty("login.brand", "pivotal");

        getMockMvc().perform(get(getAcceptInvitationLink()))
                .andExpect(content().string(containsString("Create your Pivotal ID")))
                .andExpect(content().string(containsString("Pivotal products")))
                .andExpect(content().string(not(containsString("Create your account"))))
                .andExpect(content().string(containsString("Create Pivotal ID")))
                .andExpect(content().string(not(containsString("Create account"))));
    }

    @Test
    public void testAcceptInvitationEmailWithinZone() throws Exception {
        String subdomain = generator.generate();
        mockMvcUtils.createOtherIdentityZone(subdomain, getMockMvc(), getWebApplicationContext());
        ((MockEnvironment) getWebApplicationContext().getEnvironment()).setProperty("login.brand", "pivotal");

        getMockMvc().perform(get(getAcceptInvitationLink())
                .with(new SetServerNameRequestPostProcessor(subdomain + ".localhost")))
                .andExpect(content().string(containsString("Create your account")))
                .andExpect(content().string(not(containsString("Pivotal ID"))))
                .andExpect(content().string(not(containsString("Create Pivotal ID"))))
                .andExpect(content().string(containsString("Create account")));
    }

    private String getAcceptInvitationLink() throws Exception {
        String email = generator.generate() + "@example.com";
        getMockMvc().perform(post("/invitations/new.do")
                .with(securityContext(setupSecurityContext())).with(csrf())
                .param("email", email))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("sent"));

        Iterator receivedEmail = mailServer.getReceivedEmail();
        SmtpMessage message = (SmtpMessage) receivedEmail.next();
        return mockMvcTestClient.extractLink(message.getBody());
    }

    private SecurityContext setupSecurityContext() {
        return mockMvcUtils.getMarissaSecurityContext(getWebApplicationContext());
    }

}
