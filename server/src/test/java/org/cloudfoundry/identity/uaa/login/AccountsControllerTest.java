package org.cloudfoundry.identity.uaa.login;

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
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
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
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.net.URL;
import java.util.Arrays;
import java.util.Collections;

import static org.junit.Assert.assertNull;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.xpath;

@ExtendWith(SpringExtension.class)
@ExtendWith(PollutionPreventionExtension.class)
@WebAppConfiguration
@ContextConfiguration(classes = AccountsControllerTest.ContextConfiguration.class)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class AccountsControllerTest {

    public static final String CLIENT_ID = "client_id";
    public static final String CLIENT_ID_VALUE = "app";
    public static final String REDIRECT_URI = "redirect_uri";
    public static final String REDIRECT_URI_VALUE = "http://example.com/redirect";

    @Autowired
    WebApplicationContext webApplicationContext;

    @Autowired
    AccountCreationService accountCreationService;

    @Autowired
    IdentityProviderProvisioning identityProviderProvisioning;

    private MockMvc mockMvc;

    private boolean selfServiceToReset = false;

    @BeforeEach
    void setUp() {
        SecurityContextHolder.clearContext();
        selfServiceToReset = IdentityZoneHolder.get().getConfig().getLinks().getSelfService().isSelfServiceCreateAccountEnabled();
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
                .build();
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
        IdentityZoneHolder.get().getConfig().getLinks().getSelfService().setSelfServiceCreateAccountEnabled(selfServiceToReset);
    }

    @Test
    void newAccountPage() throws Exception {
        mockMvc.perform(get("/create_account").param(CLIENT_ID, CLIENT_ID_VALUE).param(REDIRECT_URI, REDIRECT_URI_VALUE))
                .andExpect(status().isOk())
                .andExpect(model().attribute(CLIENT_ID, CLIENT_ID_VALUE))
                .andExpect(model().attribute(REDIRECT_URI, REDIRECT_URI_VALUE))
                .andExpect(view().name("accounts/new_activation_email"))
                .andExpect(xpath("//*[@type='hidden' and @value='"+CLIENT_ID_VALUE+"']").exists())
                .andExpect(xpath("//*[@type='hidden' and @value='"+REDIRECT_URI_VALUE+"']").exists());
    }

    @Test
    void testCreateAccountWithSelfServiceDisabled() throws Exception {
        IdentityZoneHolder.get().getConfig().getLinks().getSelfService().setSelfServiceCreateAccountEnabled(false);
        mockMvc.perform(get("/create_account")
                            .param(CLIENT_ID, CLIENT_ID_VALUE)
                            .param(REDIRECT_URI, REDIRECT_URI_VALUE))
               .andExpect(status().isNotFound())
               .andExpect(view().name("error"))
               .andExpect(model().attribute("error_message_code", "self_service_create_account_disabled"));
    }

    @Test
    void sendActivationEmail() throws Exception {
        MockHttpServletRequestBuilder post = post("/create_account.do")
            .param("email", "user1@example.com")
            .param("password", "password")
            .param("password_confirmation", "password")
            .param(CLIENT_ID, CLIENT_ID_VALUE)
            .param(REDIRECT_URI, REDIRECT_URI_VALUE);

        mockMvc.perform(post)
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("accounts/email_sent"));

        Mockito.verify(accountCreationService).beginActivation("user1@example.com", "password", CLIENT_ID_VALUE, REDIRECT_URI_VALUE);
    }

    @Test
    void attemptCreateAccountWithEmailDomainRestriction() throws Exception {
        MockHttpSession session = new MockHttpSession();
        MockHttpServletRequestBuilder post = post("/create_account.do")
            .session(session)
            .param("email", "user1@example.com")
            .param("password", "password")
            .param("password_confirmation", "password")
            .param(CLIENT_ID, CLIENT_ID_VALUE)
            .param(REDIRECT_URI, REDIRECT_URI_VALUE);
        IdentityProvider<OIDCIdentityProviderDefinition> oidcProvider = new IdentityProvider().setActive(true).setType(OriginKeys.OIDC10).setOriginKey(OriginKeys.OIDC10).setConfig(new OIDCIdentityProviderDefinition());
        oidcProvider.getConfig().setAuthUrl(new URL("http://localhost:8080/uaa/idp_login"));
        oidcProvider.getConfig().setEmailDomain(Collections.singletonList("example.com"));
        when(identityProviderProvisioning.retrieveAll(true, OriginKeys.UAA)).thenReturn(Collections.singletonList(oidcProvider));

        mockMvc.perform(post)
            .andExpect(view().name("accounts/new_activation_email"))
            .andExpect(model().attribute("error_message_code", "other_idp"));

        Mockito.verify(accountCreationService, times(0)).beginActivation("user1@example.com", "password", CLIENT_ID_VALUE, REDIRECT_URI_VALUE);
    }

    @Test
    void sendActivationEmailWithUserNameConflict() throws Exception {
        doThrow(new UaaException("username already exists", 409)).when(accountCreationService).beginActivation("user1" + "@example.com", "password", CLIENT_ID_VALUE, null);

        MockHttpServletRequestBuilder post = post("/create_account.do")
            .param("email", "user1@example.com")
            .param("password", "password")
            .param("password_confirmation", "password")
            .param(CLIENT_ID, CLIENT_ID_VALUE);

        mockMvc.perform(post)
            .andExpect(status().isUnprocessableEntity())
            .andExpect(view().name("accounts/new_activation_email"))
            .andExpect(model().attribute("error_message_code", "username_exists"));

        Mockito.verify(accountCreationService).beginActivation("user1@example.com", "password", CLIENT_ID_VALUE, null);
    }

    @Test
    void invalidPassword() throws Exception {
        doThrow(new InvalidPasswordException(Arrays.asList("Msg 2", "Msg 1"))).when(accountCreationService).beginActivation("user1@example.com", "password", CLIENT_ID_VALUE, null);

        MockHttpServletRequestBuilder post = post("/create_account.do")
                .param("email", "user1@example.com")
                .param("password", "password")
                .param("password_confirmation", "password")
                .param(CLIENT_ID, CLIENT_ID_VALUE);

        mockMvc.perform(post)
                .andExpect(status().isUnprocessableEntity())
                .andExpect(view().name("accounts/new_activation_email"))
                .andExpect(model().attribute("error_message", "Msg 1 Msg 2"));
    }

    @Test
    void invalidEmail() throws Exception {
        MockHttpServletRequestBuilder post = post("/create_account.do")
            .param("email", "wrong")
            .param("password", "password")
            .param("password_confirmation", "password")
            .param(CLIENT_ID, CLIENT_ID_VALUE);

        mockMvc.perform(post)
            .andExpect(status().isUnprocessableEntity())
            .andExpect(view().name("accounts/new_activation_email"))
            .andExpect(model().attribute("error_message_code", "invalid_email"));
    }

    @Test
    void passwordMismatch() throws Exception {
        MockHttpServletRequestBuilder post = post("/create_account.do")
            .param("email", "user1@example.com")
            .param("password", "pass")
            .param("password_confirmation", "word")
            .param(CLIENT_ID, CLIENT_ID_VALUE);

        IdentityZoneHolder.get().getConfig().getLinks().getSelfService().setSelfServiceCreateAccountEnabled(true);

        mockMvc.perform(post)
            .andExpect(status().isUnprocessableEntity())
            .andExpect(view().name("accounts/new_activation_email"))
            .andExpect(model().attribute("error_message_code", "form_error"));
    }


    @Test
    void verifyUser() throws Exception {
        when(accountCreationService.completeActivation("the_secret_code"))
            .thenReturn(new AccountCreationService.AccountCreationResponse("newly-created-user-id", "username", "user@example.com", "//example.com/callback"));

        MockHttpServletRequestBuilder get = get("/verify_user")
                .param("code", "the_secret_code");

        mockMvc.perform(get)
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/login?success=verify_success&form_redirect_uri=//example.com/callback"));

        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @EnableWebMvc
    @Import(ThymeleafConfig.class)
    static class ContextConfiguration implements WebMvcConfigurer {

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
