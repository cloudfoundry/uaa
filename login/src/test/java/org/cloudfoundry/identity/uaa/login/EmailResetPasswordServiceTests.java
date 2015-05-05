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

import java.sql.Timestamp;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Map;

import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.contains;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.login.test.ThymeleafConfig;
import org.cloudfoundry.identity.uaa.scim.ScimMeta;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.endpoints.PasswordResetEndpoints;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.hamcrest.Matchers;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.thymeleaf.spring4.SpringTemplateEngine;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = ThymeleafConfig.class)
public class EmailResetPasswordServiceTests {

    private EmailResetPasswordService emailResetPasswordService;
    private MessageService messageService;

    @Autowired
    @Qualifier("mailTemplateEngine")
    SpringTemplateEngine templateEngine;

    private PasswordResetEndpoints passwordResetEndpoints;
    private ExpiringCodeStore codeStore;
    private ScimUserProvisioning scimUserProvisioning;
    private UaaUrlUtils uaaUrlUtils;

    @Before
    public void setUp() throws Exception {
        SecurityContextHolder.clearContext();
        messageService = mock(EmailService.class);
        scimUserProvisioning = mock(ScimUserProvisioning.class);
        codeStore = mock(ExpiringCodeStore.class);
        passwordResetEndpoints = new PasswordResetEndpoints(scimUserProvisioning, codeStore);
        uaaUrlUtils = new UaaUrlUtils("http://uaa.example.com/uaa");
        emailResetPasswordService = new EmailResetPasswordService(templateEngine, messageService, passwordResetEndpoints, uaaUrlUtils, "pivotal");
    }

    @After
    public void tearDown() {
        SecurityContextHolder.clearContext();
        IdentityZoneHolder.clear();
    }

    @Test
    public void testForgotPasswordWhenAResetCodeIsReturnedByTheUaa() throws Exception {
        ScimUser user = new ScimUser("user-id-001","user@example.com","firstName","lastName");
        user.setPrimaryEmail("user@example.com");
        when(scimUserProvisioning.query(contains("origin"))).thenReturn(Arrays.asList(user));
        when(codeStore.generateCode(anyString(), any(Timestamp.class))).thenReturn(new ExpiringCode("code", new Timestamp(System.currentTimeMillis()),"user-id-001"));
        emailResetPasswordService.forgotPassword("user@example.com");

        Mockito.verify(messageService).sendMessage(eq("user-id-001"),
            eq("user@example.com"),
            eq(MessageType.PASSWORD_RESET),
            eq("Pivotal account password reset request"),
            contains("<a href=\"http://uaa.example.com/uaa/reset_password?code=code&amp;email=user%40example.com\">Reset your password</a>")
        );
    }

    @Test
    public void testResetPasswordInOtherZone() throws Exception {
        ScimUser user = new ScimUser("user-id-001","user@example.com","firstName","lastName");
        user.setPrimaryEmail("user@example.com");
        when(scimUserProvisioning.query(contains("origin"))).thenReturn(Arrays.asList(new ScimUser[]{user}));
        when(codeStore.generateCode(anyString(), any(Timestamp.class))).thenReturn(new ExpiringCode("code", new Timestamp(System.currentTimeMillis()),"user-id-001"));

        IdentityZoneHolder.set(MultitenancyFixture.identityZone("test-zone-id", "test"));

        emailResetPasswordService.forgotPassword("user@example.com");

        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);

        Mockito.verify(messageService).sendMessage(eq("user-id-001"),
                eq("user@example.com"),
                eq(MessageType.PASSWORD_RESET),
                eq("The Twiglet Zone account password reset request"),
                captor.capture()
        );

        String emailContent = captor.getValue();
        assertThat(emailContent, containsString(String.format("A request has been made to reset your %s account password for %s", "The Twiglet Zone", "user@example.com")));
        assertThat(emailContent, containsString("<a href=\"http://test.uaa.example.com/uaa/reset_password?code=code&amp;email=user%40example.com\">Reset your password</a>"));
        assertThat(emailContent, containsString("Thank you,<br />\n    The Twiglet Zone"));
    }

    @Test
    public void testForgotPasswordWhenConflictIsReturnedByTheUaa() throws Exception {
        ScimUser user = new ScimUser("user-id-001","user@example.com","firstName","lastName");
        user.setPrimaryEmail("user@example.com");
        when(scimUserProvisioning.query(contains("origin"))).thenReturn(Arrays.asList(new ScimUser[]{}));
        when(scimUserProvisioning.query(eq("userName eq \"user@example.com\""))).thenReturn(Arrays.asList(new ScimUser[]{user}));
        when(codeStore.generateCode(anyString(), any(Timestamp.class))).thenReturn(new ExpiringCode("code", new Timestamp(System.currentTimeMillis()), "user-id-001"));
        when(codeStore.retrieveCode(anyString())).thenReturn(new ExpiringCode("code", new Timestamp(System.currentTimeMillis()),"user-id-001"));

        emailResetPasswordService.forgotPassword("user@example.com");

        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);

        Mockito.verify(messageService).sendMessage(eq("user-id-001"),
            eq("user@example.com"),
            eq(MessageType.PASSWORD_RESET),
            eq("Pivotal account password reset request"),
            captor.capture()
        );

        String emailContent = captor.getValue();
        assertThat(emailContent, containsString(String.format("A request has been made to reset your %s account password for %s", "Pivotal", "user@example.com")));
        assertThat(emailContent, containsString("Your account credentials for uaa.example.com are managed by an external service. Please contact your administrator for password recovery requests."));
        assertThat(emailContent, containsString("Thank you,<br />\n    Pivotal"));
    }

    @Test
    public void testForgotPasswordInOtherZoneWhenConflictIsReturnedByTheUaa() throws Exception {
        ScimUser user = new ScimUser("user-id-001","user@example.com","firstName","lastName");
        user.setPrimaryEmail("user@example.com");
        when(scimUserProvisioning.query(contains("origin"))).thenReturn(Arrays.asList(new ScimUser[]{}));
        when(scimUserProvisioning.query(eq("userName eq \"user@example.com\""))).thenReturn(Arrays.asList(new ScimUser[]{user}));
        when(codeStore.generateCode(anyString(), any(Timestamp.class))).thenReturn(new ExpiringCode("code", new Timestamp(System.currentTimeMillis()), "user-id-001"));
        when(codeStore.retrieveCode(anyString())).thenReturn(new ExpiringCode("code", new Timestamp(System.currentTimeMillis()),"user-id-001"));

        IdentityZoneHolder.set(MultitenancyFixture.identityZone("test-zone-id", "test"));

        emailResetPasswordService.forgotPassword("user@example.com");

        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);

        Mockito.verify(messageService).sendMessage(eq("user-id-001"),
                eq("user@example.com"),
                eq(MessageType.PASSWORD_RESET),
                eq("The Twiglet Zone account password reset request"),
                captor.capture()
        );

        String emailBody = captor.getValue();
        assertThat(emailBody, containsString("Your account credentials for test.uaa.example.com are managed by an external service. Please contact your administrator for password recovery requests."));
        assertThat(emailBody, containsString("Thank you,<br />\n    The Twiglet Zone"));
    }

    @Test
    public void testForgotPasswordWhenTheCodeIsDenied() throws Exception {
        emailResetPasswordService.forgotPassword("user@example.com");

        Mockito.verifyZeroInteractions(messageService);
    }

    @Test
    public void testResetPassword() throws Exception {
        ScimUser user = new ScimUser("usermans-id","userman","firstName","lastName");
        user.setMeta(new ScimMeta(new Date(System.currentTimeMillis()-(1000*60*60*24)), new Date(System.currentTimeMillis()-(1000*60*60*24)), 0));
        user.setPrimaryEmail("user@example.com");
        when(scimUserProvisioning.retrieve(eq("usermans-id"))).thenReturn(user);
        when(codeStore.retrieveCode(eq("secret_code"))).thenReturn(new ExpiringCode("code", new Timestamp(System.currentTimeMillis()), "usermans-id"));
        SecurityContext securityContext = mock(SecurityContext.class);
        when(securityContext.getAuthentication()).thenReturn(new Authentication() {
            @Override
            public Collection<? extends GrantedAuthority> getAuthorities() {
                return null;
            }

            @Override
            public Object getCredentials() {
                return null;
            }

            @Override
            public Object getDetails() {
                return null;
            }

            @Override
            public Object getPrincipal() {
                return null;
            }

            @Override
            public boolean isAuthenticated() {
                return false;
            }

            @Override
            public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {

            }

            @Override
            public String getName() {
                return null;
            }
        });
        SecurityContextHolder.setContext(securityContext);

        Map<String,String> userInfo = emailResetPasswordService.resetPassword("secret_code", "new_secret");

        Assert.assertThat(userInfo, Matchers.hasEntry("user_id", "usermans-id"));
        Assert.assertThat(userInfo, Matchers.hasEntry("username", "userman"));
    }

    @Test(expected = UaaException.class)
    public void testResetPasswordWhenTheCodeIsDenied() throws Exception {
        emailResetPasswordService.resetPassword("b4d_k0d3z", "new_password");
    }
}
