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
package org.cloudfoundry.identity.uaa.login;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.contains;
import static org.mockito.Matchers.eq;
import static org.mockito.Matchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.login.test.ThymeleafConfig;
import org.cloudfoundry.identity.uaa.scim.endpoints.ChangeEmailEndpoints;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.thymeleaf.spring4.SpringTemplateEngine;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = ThymeleafConfig.class)
public class EmailChangeEmailServiceTest {
    private EmailChangeEmailService emailChangeEmailService;
    private ChangeEmailEndpoints endpoints;
    private MessageService messageService;
    private MockHttpServletRequest request;
    private UaaUrlUtils uaaUrlUtils;

    @Autowired
    @Qualifier("mailTemplateEngine")
    SpringTemplateEngine templateEngine;

    @After
    public void tearDown() throws Exception {
        SecurityContextHolder.clearContext();
        IdentityZoneHolder.clear();
    }

    @Before
    public void setUp() throws Exception {
        SecurityContextHolder.clearContext();
        endpoints = mock(ChangeEmailEndpoints.class);
        messageService = mock(EmailService.class);
        uaaUrlUtils = new UaaUrlUtils("http://uaa.example.com/uaa");
        emailChangeEmailService = new EmailChangeEmailService(templateEngine, messageService, endpoints, uaaUrlUtils, "pivotal");

        request = new MockHttpServletRequest();
        request.setProtocol("http");
        request.setContextPath("/login");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
    }

    @Test
    public void beginEmailChange() throws Exception {
        when(endpoints.generateEmailVerificationCode(any(ChangeEmailEndpoints.EmailChange.class))).thenReturn(new ResponseEntity<>("the_secret_code", HttpStatus.CREATED));
        emailChangeEmailService.beginEmailChange("user-001", "user@example.com", "new@example.com", "app");

        verify(endpoints).generateEmailVerificationCode(any(ChangeEmailEndpoints.EmailChange.class));

        Mockito.verify(messageService).sendMessage((String) isNull(),
            eq("new@example.com"),
            eq(MessageType.CHANGE_EMAIL),
            eq("Pivotal Email change verification"),
            contains("<a href=\"http://uaa.example.com/uaa/verify_email?code=the_secret_code\">Verify your email</a>")
        );
    }

    @Test
    public void testBeginEmailChangeWithOssBrand() throws Exception {
        emailChangeEmailService = new EmailChangeEmailService(templateEngine, messageService, endpoints, uaaUrlUtils, "oss");

        when(endpoints.generateEmailVerificationCode(any(ChangeEmailEndpoints.EmailChange.class))).thenReturn(new ResponseEntity<>("the_secret_code", HttpStatus.CREATED));
        emailChangeEmailService.beginEmailChange("user-001", "user@example.com", "new@example.com", "app");

        verify(endpoints).generateEmailVerificationCode(any(ChangeEmailEndpoints.EmailChange.class));

        ArgumentCaptor<String> emailBodyArgument = ArgumentCaptor.forClass(String.class);
        Mockito.verify(messageService).sendMessage((String) isNull(),
            eq("new@example.com"),
            eq(MessageType.CHANGE_EMAIL),
            eq("Account Email change verification"),
            emailBodyArgument.capture()
        );

        String emailBody = emailBodyArgument.getValue();

        assertThat(emailBody, containsString("<a href=\"http://uaa.example.com/uaa/verify_email?code=the_secret_code\">Verify your email</a>"));
        assertThat(emailBody, containsString("an account"));
        assertThat(emailBody, containsString("Cloud Foundry"));
        assertThat(emailBody, not(containsString("a Pivotal ID")));
    }

    @Test
    public void testBeginEmailChangeInOtherZone() throws Exception {
        IdentityZoneHolder.set(MultitenancyFixture.identityZone("test-zone-id", "test"));

        when(endpoints.generateEmailVerificationCode(any(ChangeEmailEndpoints.EmailChange.class))).thenReturn(new ResponseEntity<>("the_secret_code", HttpStatus.CREATED));
        emailChangeEmailService.beginEmailChange("user-001", "user@example.com", "new@example.com", "app");

        verify(endpoints).generateEmailVerificationCode(any(ChangeEmailEndpoints.EmailChange.class));

        ArgumentCaptor<String> emailBodyArgument = ArgumentCaptor.forClass(String.class);
        Mockito.verify(messageService).sendMessage((String) isNull(),
                eq("new@example.com"),
                eq(MessageType.CHANGE_EMAIL),
                eq("The Twiglet Zone Email change verification"),
                emailBodyArgument.capture()
        );

        String emailBody = emailBodyArgument.getValue();

        assertThat(emailBody, containsString(String.format("A request has been made to change the email for %s from %s to %s", "The Twiglet Zone", "user@example.com", "new@example.com")));
        assertThat(emailBody, containsString("<a href=\"http://test.uaa.example.com/uaa/verify_email?code=the_secret_code\">Verify your email</a>"));
        assertThat(emailBody, containsString("Thank you,<br />\n    The Twiglet Zone"));
    }

    @Test(expected = UaaException.class)
    public void beginEmailChangeWithUsernameConflict() throws Exception {
        ResponseEntity<String> responseEntity = new ResponseEntity<>(HttpStatus.CONFLICT);
        when(endpoints.generateEmailVerificationCode(any(ChangeEmailEndpoints.EmailChange.class))).thenReturn(responseEntity);
        emailChangeEmailService.beginEmailChange("user-001", "user@example.com", "new@example.com", null);
    }

    @Test
    public void testCompleteVerification() throws Exception {
        ChangeEmailEndpoints.EmailChangeResponse response = new ChangeEmailEndpoints.EmailChangeResponse();
        response.setUserId("user_id");
        response.setEmail("email@email.com");
        response.setUserId("username");
        ResponseEntity<ChangeEmailEndpoints.EmailChangeResponse> responseEntity = new ResponseEntity<>(response, HttpStatus.OK);
        when(endpoints.changeEmail(eq("the_secret_code"))).thenReturn(responseEntity);
        emailChangeEmailService.completeVerification("the_secret_code");
        verify(endpoints).changeEmail(eq("the_secret_code"));

    }

    @Test(expected = UaaException.class)
    public void testCompleteVerificationWithInvalidCode() throws Exception {
        ChangeEmailEndpoints.EmailChangeResponse response = new ChangeEmailEndpoints.EmailChangeResponse();
        response.setUserId("user_id");
        response.setEmail("email@email.com");
        response.setUserId("username");
        ResponseEntity<ChangeEmailEndpoints.EmailChangeResponse> responseEntity = new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
        when(endpoints.changeEmail(eq("the_secret_code"))).thenReturn(responseEntity);
        emailChangeEmailService.completeVerification("the_secret_code");
    }

}