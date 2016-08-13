/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
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

import org.cloudfoundry.identity.uaa.TestClassNullifier;
import org.cloudfoundry.identity.uaa.account.ConflictException;
import org.cloudfoundry.identity.uaa.account.ForgotPasswordInfo;
import org.cloudfoundry.identity.uaa.account.NotFoundException;
import org.cloudfoundry.identity.uaa.account.ResetPasswordController;
import org.cloudfoundry.identity.uaa.account.ResetPasswordService;
import org.cloudfoundry.identity.uaa.account.ResetPasswordService.ResetPasswordResponse;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.login.test.ThymeleafConfig;
import org.cloudfoundry.identity.uaa.message.MessageService;
import org.cloudfoundry.identity.uaa.message.MessageType;
import org.cloudfoundry.identity.uaa.scim.ScimMeta;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.zone.*;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.servlet.view.InternalResourceViewResolver;
import org.thymeleaf.spring4.SpringTemplateEngine;

import java.sql.Timestamp;
import java.util.Arrays;
import java.util.Date;

import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.contains;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = ThymeleafConfig.class)
public class ResetPasswordControllerTest extends TestClassNullifier {
    private MockMvc mockMvc;
    private ResetPasswordService resetPasswordService;
    private MessageService messageService;
    private ExpiringCodeStore codeStore;
    private UaaUserDatabase userDatabase;
    private String companyName = "Best Company";

    @Autowired
    @Qualifier("mailTemplateEngine")
    private SpringTemplateEngine templateEngine;

    @Before
    public void setUp() throws Exception {
        SecurityContextHolder.clearContext();
        IdentityZoneHolder.set(IdentityZone.getUaa());
        resetPasswordService = mock(ResetPasswordService.class);
        messageService = mock(MessageService.class);
        codeStore = mock(ExpiringCodeStore.class);
        userDatabase = mock(UaaUserDatabase.class);
        when(userDatabase.retrieveUserById(anyString())).thenReturn(new UaaUser("username","password","email","givenname","familyname"));
        ResetPasswordController controller = new ResetPasswordController(resetPasswordService, messageService, templateEngine, codeStore, userDatabase);

        InternalResourceViewResolver viewResolver = new InternalResourceViewResolver();
        viewResolver.setPrefix("/WEB-INF/jsp");
        viewResolver.setSuffix(".jsp");
        mockMvc = MockMvcBuilders
            .standaloneSetup(controller)
            .setViewResolvers(viewResolver)
            .build();
    }

    @After
    public void tearDown() {
        SecurityContextHolder.clearContext();
        IdentityZoneHolder.set(IdentityZone.getUaa());
    }

    @Test
    public void testForgotPasswordPage() throws Exception {
        mockMvc.perform(get("/forgot_password")
            .param("client_id", "example")
            .param("redirect_uri", "http://example.com"))
            .andExpect(status().isOk())
            .andExpect(view().name("forgot_password"))
            .andExpect(model().attribute("client_id", "example"))
            .andExpect(model().attribute("redirect_uri", "http://example.com"));
    }

    @Test
    public void forgotPassword_Conflict_SendsEmailWithUnavailableEmailHtml() throws Exception {
        forgotPasswordWithConflict(null, companyName);
    }

    @Test
    public void forgotPassword_ConflictInOtherZone_SendsEmailWithUnavailableEmailHtml() throws Exception {
        String subdomain = "testsubdomain";
        IdentityZoneHolder.set(MultitenancyFixture.identityZone("test-zone-id", subdomain));
        forgotPasswordWithConflict(subdomain, "The Twiglet Zone");
    }

    private void forgotPasswordWithConflict(String zoneDomain, String companyName) throws Exception {
        IdentityZoneConfiguration defaultConfig = IdentityZoneHolder.get().getConfig();
        BrandingInformation branding = new BrandingInformation();
        branding.setCompanyName(companyName);
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.setBranding(branding);
        IdentityZoneHolder.get().setConfig(config);

        try {
            new ResetPasswordController(resetPasswordService, messageService, templateEngine, codeStore, userDatabase);
            String domain = zoneDomain == null ? "localhost" : zoneDomain + ".localhost";
            when(resetPasswordService.forgotPassword("user@example.com", "", "")).thenThrow(new ConflictException("abcd"));
            MockHttpServletRequestBuilder post = post("/forgot_password.do")
              .contentType(APPLICATION_FORM_URLENCODED)
              .param("email", "user@example.com");

            post.with(request -> {
                request.setServerName(domain);
                return request;
            });

            mockMvc.perform(post)
              .andExpect(status().isFound())
              .andExpect(redirectedUrl("email_sent?code=reset_password"));
            ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);

            Mockito.verify(messageService).sendMessage(
              eq("user@example.com"),
              eq(MessageType.PASSWORD_RESET),
              eq(companyName + " account password reset request"),
              captor.capture()
            );

            String emailContent = captor.getValue();
            assertThat(emailContent, containsString(String.format("A request has been made to reset your %s account password for %s", companyName, "user@example.com")));
            assertThat(emailContent, containsString("Your account credentials for " + domain + " are managed by an external service. Please contact your administrator for password recovery requests."));
            assertThat(emailContent, containsString("Thank you,<br />\n    " + companyName));
        } finally {
            IdentityZoneHolder.get().setConfig(defaultConfig);
        }
    }

    @Test
    public void forgotPassword_DoesNotSendEmail_UserNotFound() throws Exception {
        when(resetPasswordService.forgotPassword("user@example.com", "", "")).thenThrow(new NotFoundException());
        MockHttpServletRequestBuilder post = post("/forgot_password.do")
            .contentType(APPLICATION_FORM_URLENCODED)
            .param("email", "user@example.com");
        mockMvc.perform(post)
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("email_sent?code=reset_password"));

        Mockito.verifyZeroInteractions(messageService);
    }

    @Test
    public void forgotPassword_Successful() throws Exception {
        forgotPasswordSuccessful("http://localhost/reset_password?code=code1");
    }

    @Test
    public void forgotPassword_SuccessfulDefaultCompanyName() throws Exception {
        ResetPasswordController controller = new ResetPasswordController(resetPasswordService, messageService, templateEngine, codeStore, userDatabase);
        InternalResourceViewResolver viewResolver = new InternalResourceViewResolver();
        viewResolver.setPrefix("/WEB-INF/jsp");
        viewResolver.setSuffix(".jsp");
        mockMvc = MockMvcBuilders
                .standaloneSetup(controller)
                .setViewResolvers(viewResolver)
                .build();
        forgotPasswordSuccessful("http://localhost/reset_password?code=code1", "Cloud Foundry", null);
    }

    @Test
    public void forgotPassword_SuccessfulInOtherZone() throws Exception {
        IdentityZone zone = MultitenancyFixture.identityZone("test-zone-id", "testsubdomain");
        IdentityZoneHolder.set(zone);
        forgotPasswordSuccessful("http://testsubdomain.localhost/reset_password?code=code1", "The Twiglet Zone", zone);
    }

    private void forgotPasswordSuccessful(String url) throws Exception {
        forgotPasswordSuccessful(url, "Best Company", null);
    }

    private void forgotPasswordSuccessful(String url, String companyName, IdentityZone zone) throws Exception {
        IdentityZoneConfiguration defaultConfig = IdentityZoneHolder.get().getConfig();
        BrandingInformation branding = new BrandingInformation();
        branding.setCompanyName(companyName);
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.setBranding(branding);
        IdentityZoneHolder.get().setConfig(config);
        try {
            when(resetPasswordService.forgotPassword("user@example.com", "example", "redirect.example.com")).thenReturn(new ForgotPasswordInfo("123", new ExpiringCode("code1", new Timestamp(System.currentTimeMillis()), "someData", null)));
            MockHttpServletRequestBuilder post = post("/forgot_password.do")
              .contentType(APPLICATION_FORM_URLENCODED)
              .param("email", "user@example.com")
              .param("client_id", "example")
              .param("redirect_uri", "redirect.example.com");

            if (zone != null) {
                post.with(request -> {
                    request.setServerName(zone.getSubdomain() + ".localhost");
                    return request;
                });
            }

            mockMvc.perform(post)
              .andExpect(status().isFound())
              .andExpect(redirectedUrl("email_sent?code=reset_password"));
            verify(messageService).sendMessage(
              eq("user@example.com"),
              eq(MessageType.PASSWORD_RESET),
              eq(companyName + " account password reset request"),
              contains("<a href=\"" + url + "\">Reset your password</a>")
            );
        } finally {
            IdentityZoneHolder.get().setConfig(defaultConfig);
        }
    }

    @Test
    public void testForgotPasswordFormValidationFailure() throws Exception {
        MockHttpServletRequestBuilder post = post("/forgot_password.do")
            .contentType(APPLICATION_FORM_URLENCODED)
            .param("email", "notAnEmail");
        mockMvc.perform(post)
            .andExpect(status().isUnprocessableEntity())
            .andExpect(view().name("forgot_password"))
            .andExpect(model().attribute("message_code", "form_error"));

        verifyZeroInteractions(resetPasswordService);
    }

    @Test
    public void testInstructions() throws Exception {
        mockMvc.perform(get("/email_sent").param("code", "reset_password"))
            .andExpect(status().isOk())
            .andExpect(model().attribute("code", "reset_password"));
    }

    @Test
    public void testResetPasswordPage() throws Exception {
        ExpiringCode code = new ExpiringCode("code1", new Timestamp(System.currentTimeMillis()), "{\"user_id\" : \"some-user-id\"}", null);
        when(codeStore.generateCode(anyString(), any(Timestamp.class), eq(null))).thenReturn(code);
        when(codeStore.retrieveCode(anyString())).thenReturn(code);
        mockMvc.perform(get("/reset_password").param("email", "user@example.com").param("code", "code1"))
            .andExpect(status().isOk())
            .andExpect(view().name("reset_password"));
    }

    @Test
    public void testResetPasswordSuccess() throws Exception {
        ScimUser user = new ScimUser("user-id", "foo@example.com", "firstName", "lastName");
        user.setMeta(new ScimMeta(new Date(System.currentTimeMillis() - (1000 * 60 * 60 * 24)), new Date(System.currentTimeMillis() - (1000 * 60 * 60 * 24)), 0));
        user.setPrimaryEmail("foo@example.com");
        when(resetPasswordService.resetPassword("secret_code", "password")).thenReturn(new ResetPasswordResponse(user, "redirect.example.com", null));

        MockHttpServletRequestBuilder post = post("/reset_password.do")
            .contentType(APPLICATION_FORM_URLENCODED)
            .param("code", "secret_code")
            .param("email", "foo@example.com")
            .param("password", "password")
            .param("password_confirmation", "password");
        mockMvc.perform(post)
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("redirect.example.com"))
            .andExpect(model().attributeDoesNotExist("code"))
            .andExpect(model().attributeDoesNotExist("password"))
            .andExpect(model().attributeDoesNotExist("password_confirmation"));
    }

    @Test
    public void testResetPasswordFormValidationFailure() throws Exception {
        MockHttpServletRequestBuilder post = post("/reset_password.do")
            .contentType(APPLICATION_FORM_URLENCODED)
            .param("code", "123456")
            .param("email", "foo@example.com")
            .param("password", "pass")
            .param("password_confirmation", "word");

        mockMvc.perform(post)
            .andExpect(status().isUnprocessableEntity())
            .andExpect(view().name("reset_password"))
            .andExpect(model().attribute("message_code", "form_error"))
            .andExpect(model().attribute("email", "foo@example.com"))
            .andExpect(model().attribute("code", "123456"));

        verifyZeroInteractions(resetPasswordService);
    }

    @Test
    public void testResetPasswordFormWithInvalidCode() throws Exception {
        when(resetPasswordService.resetPassword("bad_code", "password")).thenThrow(new UaaException("Bad code!"));

        MockHttpServletRequestBuilder post = post("/reset_password.do")
            .contentType(APPLICATION_FORM_URLENCODED)
            .param("code", "bad_code")
            .param("email", "foo@example.com")
            .param("password", "password")
            .param("password_confirmation", "password");

        mockMvc.perform(post)
            .andExpect(status().isUnprocessableEntity())
            .andExpect(view().name("forgot_password"))
            .andExpect(model().attribute("message_code", "bad_code"));

        verify(resetPasswordService).resetPassword("bad_code", "password");
    }

    @Test
    public void testResetPasswordFormWithInvalidPassword() throws Exception {
        when(resetPasswordService.resetPassword("bad_code", "password")).thenThrow(new InvalidPasswordException(Arrays.asList("Msg 2a", "Msg 1a")));

        MockHttpServletRequestBuilder post = post("/reset_password.do")
            .contentType(APPLICATION_FORM_URLENCODED)
            .param("code", "bad_code")
            .param("email", "foo@example.com")
            .param("password", "password")
            .param("password_confirmation", "password");

        mockMvc.perform(post)
            .andExpect(status().isUnprocessableEntity())
            .andExpect(view().name("forgot_password"))
            .andExpect(model().attribute("message", "Msg 1a Msg 2a"));
    }

    @Test
    public void resetPassword_Returns422UnprocessableEntity_NewPasswordSameAsOld() throws Exception {
        when(resetPasswordService.resetPassword("good_code", "n3wPasswordSam3AsOld")).
            thenThrow(new InvalidPasswordException("Your new password cannot be the same as the old password.",
                HttpStatus.UNPROCESSABLE_ENTITY));

        MockHttpServletRequestBuilder post = post("/reset_password.do")
            .contentType(APPLICATION_FORM_URLENCODED)
            .param("code", "good_code")
            .param("email", "foo@example.com")
            .param("password", "n3wPasswordSam3AsOld")
            .param("password_confirmation", "n3wPasswordSam3AsOld");

        mockMvc.perform(post)
            .andExpect(status().isUnprocessableEntity())
            .andExpect(view().name("forgot_password"))
            .andExpect(model().attribute("message", "Your new password cannot be the same as the old password."));
    }
}
