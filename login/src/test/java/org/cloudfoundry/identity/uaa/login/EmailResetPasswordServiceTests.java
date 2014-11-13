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
import java.util.Collection;
import java.util.Map;

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
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.endpoints.PasswordResetEndpoints;
import org.codehaus.jackson.map.ObjectMapper;
import org.hamcrest.Matchers;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.thymeleaf.spring4.SpringTemplateEngine;
import scala.actors.threadpool.Arrays;

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

    @Before
    public void setUp() throws Exception {
        SecurityContextHolder.clearContext();
        messageService = mock(EmailService.class);
        scimUserProvisioning = mock(ScimUserProvisioning.class);
        codeStore = mock(ExpiringCodeStore.class);
        passwordResetEndpoints = new PasswordResetEndpoints(new ObjectMapper(), scimUserProvisioning, codeStore);
        emailResetPasswordService = new EmailResetPasswordService(templateEngine, messageService, passwordResetEndpoints, "http://uaa.example.com/uaa", "pivotal");
    }

    @After
    public void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    public void testForgotPasswordWhenAResetCodeIsReturnedByTheUaa() throws Exception {

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setProtocol("http");
        request.setContextPath("/login");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

        ScimUser user = new ScimUser("user-id-001","user@example.com","firstName","lastName");
        user.setPrimaryEmail("user@example.com");
        when(scimUserProvisioning.query(contains("origin"))).thenReturn(Arrays.asList(new ScimUser[]{user}));
        when(codeStore.generateCode(anyString(), any(Timestamp.class))).thenReturn(new ExpiringCode("code", new Timestamp(System.currentTimeMillis()),"user-id-001"));
        emailResetPasswordService.forgotPassword("user@example.com");



        Mockito.verify(messageService).sendMessage(eq("user-id-001"),
            eq("user@example.com"),
            eq(MessageType.PASSWORD_RESET),
            eq("Pivotal account password reset request"),
            contains("<a href=\"http://localhost/login/reset_password?code=code&amp;email=user%40example.com\">Reset your password</a>")
        );
    }

    @Test
    public void testForgotPasswordWhenConflictIsReturnedByTheUaa() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setProtocol("http");
        request.setContextPath("/login");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

        ScimUser user = new ScimUser("user-id-001","user@example.com","firstName","lastName");
        user.setPrimaryEmail("user@example.com");
        when(scimUserProvisioning.query(contains("origin"))).thenReturn(Arrays.asList(new ScimUser[]{}));
        when(scimUserProvisioning.query(eq("userName eq \"user@example.com\""))).thenReturn(Arrays.asList(new ScimUser[]{user}));
        when(codeStore.generateCode(anyString(), any(Timestamp.class))).thenReturn(new ExpiringCode("code", new Timestamp(System.currentTimeMillis()), "user-id-001"));
        when(codeStore.retrieveCode(anyString())).thenReturn(new ExpiringCode("code", new Timestamp(System.currentTimeMillis()),"user-id-001"));

        emailResetPasswordService.forgotPassword("user@example.com");

        Mockito.verify(messageService).sendMessage(eq("user-id-001"),
            eq("user@example.com"),
            eq(MessageType.PASSWORD_RESET),
            eq("Pivotal account password reset request"),
            contains("Your account credentials for localhost are managed by an external service. Please contact your administrator for password recovery requests.")
        );
    }

    @Test
    public void testForgotPasswordWhenTheCodeIsDenied() throws Exception {
        emailResetPasswordService.forgotPassword("user@example.com");

        Mockito.verifyZeroInteractions(messageService);
    }

    @Test
    public void testResetPassword() throws Exception {
        ScimUser user = new ScimUser("usermans-id","userman","firstName","lastName");
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
