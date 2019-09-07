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
import org.cloudfoundry.identity.uaa.account.AccountCreationService;
import org.cloudfoundry.identity.uaa.account.AccountsController;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.home.BuildInfo;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.security.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.mock.web.MockHttpSession;
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

import java.net.URL;
import java.util.Arrays;
import java.util.Collections;

import static org.junit.Assert.assertNull;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@ExtendWith(SpringExtension.class)
@ExtendWith(PollutionPreventionExtension.class)
@WebAppConfiguration
@ContextConfiguration(classes = AccountsControllerTest.ContextConfiguration.class)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
public class AccountsControllerTest extends TestClassNullifier {

    @Autowired
    WebApplicationContext webApplicationContext;

    @Autowired
    AccountCreationService accountCreationService;

    @Autowired
    IdentityProviderProvisioning identityProviderProvisioning;

    private MockMvc mockMvc;

    private boolean selfServiceToReset = false;

    @BeforeEach
    public void setUp() throws Exception {
        SecurityContextHolder.clearContext();
        selfServiceToReset = IdentityZoneHolder.get().getConfig().getLinks().getSelfService().isSelfServiceLinksEnabled();
        IdentityZoneHolder.get().getConfig().getLinks().getSelfService().setSelfServiceLinksEnabled(true);
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
                .build();
    }

    @AfterEach
    public void tearDown() throws Exception {
        SecurityContextHolder.clearContext();
        IdentityZoneHolder.get().getConfig().getLinks().getSelfService().setSelfServiceLinksEnabled(selfServiceToReset);
    }

    @Test
    public void testNewAccountPage() throws Exception {
        mockMvc.perform(get("/create_account").param("client_id", "client-id").param("redirect_uri", "http://example.com/redirect"))
                .andExpect(status().isOk())
                .andExpect(model().attribute("client_id", "client-id"))
                .andExpect(model().attribute("redirect_uri", "http://example.com/redirect"))
                .andExpect(view().name("accounts/new_activation_email"))
                .andExpect(xpath("//*[@type='hidden' and @value='client-id']").exists())
                .andExpect(xpath("//*[@type='hidden' and @value='http://example.com/redirect']").exists());
    }

    @Test
    public void testSendActivationEmail() throws Exception {
        MockHttpServletRequestBuilder post = post("/create_account.do")
            .param("email", "user1@example.com")
            .param("password", "password")
            .param("password_confirmation", "password")
            .param("client_id", "app")
            .param("redirect_uri", "http://example.com/redirect");

        mockMvc.perform(post)
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("accounts/email_sent"));

        Mockito.verify(accountCreationService).beginActivation("user1@example.com", "password", "app", "http://example.com/redirect");
    }

    @Test
    public void testAttemptCreateAccountWithEmailDomainRestriction() throws Exception {
        MockHttpSession session = new MockHttpSession();
        MockHttpServletRequestBuilder post = post("/create_account.do")
            .session(session)
            .param("email", "user1@example.com")
            .param("password", "password")
            .param("password_confirmation", "password")
            .param("client_id", "app")
            .param("redirect_uri", "http://example.com/redirect");
        IdentityProvider<OIDCIdentityProviderDefinition> oidcProvider = new IdentityProvider().setActive(true).setType(OriginKeys.OIDC10).setOriginKey(OriginKeys.OIDC10).setConfig(new OIDCIdentityProviderDefinition());
        oidcProvider.getConfig().setAuthUrl(new URL("http://localhost:8080/uaa/idp_login"));
        oidcProvider.getConfig().setEmailDomain(Collections.singletonList("example.com"));
        when(identityProviderProvisioning.retrieveAll(true, OriginKeys.UAA)).thenReturn(Collections.singletonList(oidcProvider));

        mockMvc.perform(post)
            .andExpect(view().name("accounts/new_activation_email"))
            .andExpect(model().attribute("error_message_code", "other_idp"));

        Mockito.verify(accountCreationService, times(0)).beginActivation("user1@example.com", "password", "app", "http://example.com/redirect");
    }

    @Test
    public void testSendActivationEmailWithUserNameConflict() throws Exception {
        doThrow(new UaaException("username already exists", 409)).when(accountCreationService).beginActivation("user1@example.com", "password", "app", null);

        MockHttpServletRequestBuilder post = post("/create_account.do")
            .param("email", "user1@example.com")
            .param("password", "password")
            .param("password_confirmation", "password")
            .param("client_id", "app");

        mockMvc.perform(post)
            .andExpect(status().isUnprocessableEntity())
            .andExpect(view().name("accounts/new_activation_email"))
            .andExpect(model().attribute("error_message_code", "username_exists"));

        Mockito.verify(accountCreationService).beginActivation("user1@example.com", "password", "app", null);
    }

    @Test
    public void testInvalidPassword() throws Exception {
        doThrow(new InvalidPasswordException(Arrays.asList("Msg 2", "Msg 1"))).when(accountCreationService).beginActivation("user1@example.com", "password", "app", null);

        MockHttpServletRequestBuilder post = post("/create_account.do")
                .param("email", "user1@example.com")
                .param("password", "password")
                .param("password_confirmation", "password")
                .param("client_id", "app");

        mockMvc.perform(post)
                .andExpect(status().isUnprocessableEntity())
                .andExpect(view().name("accounts/new_activation_email"))
                .andExpect(model().attribute("error_message", "Msg 1 Msg 2"));
    }

    @Test
    public void testInvalidEmail() throws Exception {
        MockHttpServletRequestBuilder post = post("/create_account.do")
            .param("email", "wrong")
            .param("password", "password")
            .param("password_confirmation", "password")
            .param("client_id", "app");

        mockMvc.perform(post)
            .andExpect(status().isUnprocessableEntity())
            .andExpect(view().name("accounts/new_activation_email"))
            .andExpect(model().attribute("error_message_code", "invalid_email"));
    }

    @Test
    public void testPasswordMismatch() throws Exception {
        MockHttpServletRequestBuilder post = post("/create_account.do")
            .param("email", "user1@example.com")
            .param("password", "pass")
            .param("password_confirmation", "word")
            .param("client_id", "app");

        IdentityZoneHolder.get().getConfig().getLinks().getSelfService().setSelfServiceLinksEnabled(true);

        mockMvc.perform(post)
            .andExpect(status().isUnprocessableEntity())
            .andExpect(view().name("accounts/new_activation_email"))
            .andExpect(model().attribute("error_message_code", "form_error"));
    }


    @Test
    public void testVerifyUser() throws Exception {
        when(accountCreationService.completeActivation("the_secret_code"))
            .thenReturn(new AccountCreationService.AccountCreationResponse("newly-created-user-id", "username", "user@example.com", "//example.com/callback"));

        MockHttpServletRequestBuilder get = get("/verify_user")
                .param("code", "the_secret_code");

        mockMvc.perform(get)
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/login?success=verify_success&form_redirect_uri=//example.com/callback"));

        assertNull(SecurityContextHolder.getContext().getAuthentication());
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
        AccountCreationService accountCreationService() {
            return mock(AccountCreationService.class);
        }

        @Bean
        IdentityProviderProvisioning identityProviderProvisioning() {
            return mock(JdbcIdentityProviderProvisioning.class);
        }

        @Bean
        AccountsController accountsController(AccountCreationService accountCreationService, IdentityProviderProvisioning identityProviderProvisioning) {
            return new AccountsController(accountCreationService, identityProviderProvisioning);
        }
    }
}
