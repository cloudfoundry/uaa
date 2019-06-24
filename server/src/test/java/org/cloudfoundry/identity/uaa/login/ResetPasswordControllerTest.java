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
import org.cloudfoundry.identity.uaa.account.*;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.codestore.InMemoryExpiringCodeStore;
import org.cloudfoundry.identity.uaa.home.BuildInfo;
import org.cloudfoundry.identity.uaa.message.MessageService;
import org.cloudfoundry.identity.uaa.message.MessageType;
import org.cloudfoundry.identity.uaa.security.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.zone.*;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.DefaultServletHandlerConfigurer;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;
import org.thymeleaf.TemplateEngine;

import java.sql.Timestamp;

import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@ExtendWith(SpringExtension.class)
@ExtendWith(PollutionPreventionExtension.class)
@WebAppConfiguration
@ContextConfiguration(classes = ResetPasswordControllerTest.ContextConfiguration.class)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
public class ResetPasswordControllerTest extends TestClassNullifier {
    private MockMvc mockMvc;
    private String companyName = "Best Company";

    @Autowired
    WebApplicationContext webApplicationContext;

    @Autowired
    ExpiringCodeStore codeStore;

    @Autowired
    ResetPasswordService resetPasswordService;

    @Autowired
    MessageService messageService;

    @Autowired
    @Qualifier("mailTemplateEngine")
    TemplateEngine templateEngine;

    @Autowired
    UaaUserDatabase userDatabase;

    private AccountSavingAuthenticationSuccessHandler successHandler = mock(AccountSavingAuthenticationSuccessHandler.class);

    @BeforeEach
    public void setUp() throws Exception {
        SecurityContextHolder.clearContext();
        IdentityZoneHolder.set(IdentityZone.getUaa());

        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
            .build();
    }

    @AfterEach
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
    public void testForgotPasswordWithSelfServiceDisabled() throws Exception {
        IdentityZone zone = MultitenancyFixture.identityZone("test-zone-id", "testsubdomain");
        zone.getConfig().getLinks().getSelfService().setSelfServiceLinksEnabled(false);
        IdentityZoneHolder.set(zone);

        mockMvc.perform(get("/forgot_password")
                .param("client_id", "example")
                .param("redirect_uri", "http://example.com"))
                .andExpect(status().isNotFound())
                .andExpect(view().name("error"))
                .andExpect(model().attribute("error_message_code", "self_service_disabled"));
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
            String domain = zoneDomain == null ? "localhost" : zoneDomain + ".localhost";
            when(resetPasswordService.forgotPassword("user@example.com", "", "")).thenThrow(new ConflictException("abcd", "user@example.com"));
            MockHttpServletRequestBuilder post = post("/forgot_password.do")
              .contentType(APPLICATION_FORM_URLENCODED)
              .param("username", "user@example.com");

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
            .param("username", "user@example.com");
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
        mockMvc = MockMvcBuilders
                .standaloneSetup(controller)
                .setViewResolvers(getResolver())
                .build();
        forgotPasswordSuccessful("http://localhost/reset_password?code=code1", "Cloud Foundry");
    }

    @Test
    public void forgotPassword_SuccessfulInOtherZone() throws Exception {
        IdentityZone zone = MultitenancyFixture.identityZone("test-zone-id", "testsubdomain");
        IdentityZoneHolder.set(zone);
        forgotPasswordSuccessful("http://testsubdomain.localhost/reset_password?code=code1", "The Twiglet Zone");
    }

    @Test
    public void forgotPasswordPostWithSelfServiceDisabled() throws Exception {
        IdentityZone zone = MultitenancyFixture.identityZone("test-zone-id", "testsubdomain");
        zone.getConfig().getLinks().getSelfService().setSelfServiceLinksEnabled(false);
        IdentityZoneHolder.set(zone);

        mockMvc.perform(post("/forgot_password.do")
                .contentType(APPLICATION_FORM_URLENCODED)
                .param("username", "user@example.com")
                .param("client_id", "example")
                .param("redirect_uri", "redirect.example.com"))
                .andExpect(status().isNotFound())
                .andExpect(view().name("error"))
                .andExpect(model().attribute("error_message_code", "self_service_disabled"));
    }

    private void forgotPasswordSuccessful(String url) throws Exception {
        forgotPasswordSuccessful(url, "Best Company");
    }

    private void forgotPasswordSuccessful(String url, String companyName) throws Exception {
        IdentityZoneConfiguration defaultConfig = IdentityZoneHolder.get().getConfig();
        BrandingInformation branding = new BrandingInformation();
        branding.setCompanyName(companyName);
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.setBranding(branding);
        IdentityZoneHolder.get().setConfig(config);
        try {
            when(resetPasswordService.forgotPassword("user@example.com", "example", "redirect.example.com")).thenReturn(new ForgotPasswordInfo("123", "user@example.com", new ExpiringCode("code1", new Timestamp(System.currentTimeMillis()), "someData", null)));
            MockHttpServletRequestBuilder post = post("/forgot_password.do")
              .contentType(APPLICATION_FORM_URLENCODED)
              .param("username", "user@example.com")
              .param("client_id", "example")
              .param("redirect_uri", "redirect.example.com");

            if (!IdentityZoneHolder.isUaa()) {
                post.with(request -> {
                    request.setServerName(IdentityZoneHolder.get().getSubdomain() + ".localhost");
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
    public void testInstructions() throws Exception {
        mockMvc.perform(get("/email_sent").param("code", "reset_password"))
            .andExpect(status().isOk())
            .andExpect(header().string("Content-Security-Policy", "frame-ancestors 'none'"))
            .andExpect(model().attribute("code", "reset_password"));
    }

    @Test
    public void testResetPasswordPage() throws Exception {
        ExpiringCode code = codeStore.generateCode("{\"user_id\" : \"some-user-id\"}", new Timestamp(System.currentTimeMillis() + 1000000), null, IdentityZoneHolder.get().getId());
        mockMvc.perform(get("/reset_password").param("email", "user@example.com").param("code", code.getCode()))
            .andExpect(status().isOk())
            .andDo(print())
            .andExpect(view().name("reset_password"))
            .andExpect(model().attribute("email", "email"))
            .andExpect(model().attribute("username", "username"))
            .andExpect(content().string(containsString("<div class=\"email-display\">Username: username</div>")))
            .andExpect(content().string(containsString("<input type=\"hidden\" name=\"username\" value=\"username\"/>")));
    }

    @Test
    public void testResetPasswordPageDuplicate() throws Exception {
        ExpiringCode code = codeStore.generateCode("{\"user_id\" : \"some-user-id\"}", new Timestamp(System.currentTimeMillis() + 1000000), null, IdentityZoneHolder.get().getId());
        mockMvc.perform(get("/reset_password").param("email", "user@example.com").param("code", code.getCode()))
            .andExpect(status().isOk())
            .andExpect(view().name("reset_password"));
        mockMvc.perform(get("/reset_password").param("email", "user@example.com").param("code", code.getCode()))
            .andExpect(status().isUnprocessableEntity())
            .andExpect(view().name("forgot_password"));
    }

    @Test
    public void testResetPasswordPageWhenExpiringCodeNull() throws Exception {
        mockMvc.perform(get("/reset_password").param("email", "user@example.com").param("code", "code1"))
            .andExpect(status().isUnprocessableEntity())
            .andExpect(view().name("forgot_password"))
            .andExpect(model().attribute("message_code", "bad_code"));
    }


    @Configuration
    @EnableWebMvc
    @Import(ThymeleafConfig.class)
    static class ContextConfiguration extends WebMvcConfigurerAdapter {

        @Override
        public void configureDefaultServletHandling(DefaultServletHandlerConfigurer configurer) {
            configurer.enable();
        }

        @Bean
        BuildInfo buildInfo() {
            return new BuildInfo();
        }

        @Bean
        public ResourceBundleMessageSource messageSource() {
            ResourceBundleMessageSource resourceBundleMessageSource = new ResourceBundleMessageSource();
            resourceBundleMessageSource.setBasename("messages");
            return resourceBundleMessageSource;
        }

        @Bean
        public ResetPasswordService resetPasswordService() {
            return mock(ResetPasswordService.class);
        }

        @Bean
        public MessageService messageService() {
            return mock(MessageService.class);
        }

        @Bean
        public ExpiringCodeStore codeStore() {
            return new InMemoryExpiringCodeStore();
        }

        @Bean
        public UaaUserDatabase userDatabase() {
            UaaUserDatabase userDatabase = mock(UaaUserDatabase.class);
            when(userDatabase.retrieveUserById(anyString())).thenReturn(new UaaUser("username","password","email","givenname","familyname"));
            return userDatabase;
        }

        @Bean
        ResetPasswordController resetPasswordController(ResetPasswordService resetPasswordService,
                                                        MessageService messageService,
                                                        TemplateEngine mailTemplateEngine,
                                                        ExpiringCodeStore codeStore,
                                                        UaaUserDatabase userDatabase) {
            ResetPasswordController controller = new ResetPasswordController(resetPasswordService, messageService, mailTemplateEngine, codeStore, userDatabase);
            return controller;
        }
    }

}
