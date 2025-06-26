package org.cloudfoundry.identity.uaa.login;

import jakarta.annotation.PostConstruct;
import org.cloudfoundry.identity.uaa.account.AccountCreationService;
import org.cloudfoundry.identity.uaa.account.AccountsController;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.home.BuildInfo;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.util.beans.TestBuildInfo;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
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
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.DefaultServletHandlerConfigurer;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerAdapter;

import java.net.URI;
import java.util.Arrays;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.head;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.xpath;

@ExtendWith(PollutionPreventionExtension.class)
@WebAppConfiguration
@SpringJUnitConfig(classes = AccountsControllerTest.ContextConfiguration.class)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class AccountsControllerTest {

    @Autowired
    WebApplicationContext webApplicationContext;

    @Autowired
    AccountCreationService accountCreationService;

    @Autowired
    IdentityProviderProvisioning identityProviderProvisioning;

    private MockMvc mockMvc;

    private boolean selfServiceToReset;

    @BeforeEach
    void setUp() {
        SecurityContextHolder.clearContext();
        selfServiceToReset = IdentityZoneHolder.get().getConfig().getLinks().getSelfService().isSelfServiceLinksEnabled();
        IdentityZoneHolder.get().getConfig().getLinks().getSelfService().setSelfServiceLinksEnabled(true);
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
                .build();
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
        IdentityZoneHolder.get().getConfig().getLinks().getSelfService().setSelfServiceLinksEnabled(selfServiceToReset);
    }

    @Test
    void newAccountPage() throws Exception {
        mockMvc.perform(get("/create_account").param("client_id", "client-id").param("redirect_uri", "http://example.com/redirect"))
                .andExpect(status().isOk())
                .andExpect(model().attribute("client_id", "client-id"))
                .andExpect(model().attribute("redirect_uri", "http://example.com/redirect"))
                .andExpect(view().name("accounts/new_activation_email"))
                .andExpect(xpath("//*[@type='hidden' and @value='client-id']").exists())
                .andExpect(xpath("//*[@type='hidden' and @value='http://example.com/redirect']").exists());
    }

    @Test
    void sendActivationEmail() throws Exception {
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
    void attemptCreateAccountWithEmailDomainRestriction() throws Exception {
        MockHttpSession session = new MockHttpSession();
        MockHttpServletRequestBuilder post = post("/create_account.do")
                .session(session)
                .param("email", "user1@example.com")
                .param("password", "password")
                .param("password_confirmation", "password")
                .param("client_id", "app")
                .param("redirect_uri", "http://example.com/redirect");
        IdentityProvider<OIDCIdentityProviderDefinition> oidcProvider = new IdentityProvider().setActive(true).setType(OriginKeys.OIDC10).setOriginKey(OriginKeys.OIDC10).setConfig(new OIDCIdentityProviderDefinition());
        oidcProvider.getConfig().setAuthUrl(URI.create("http://localhost:8080/uaa/idp_login").toURL());
        oidcProvider.getConfig().setEmailDomain(Collections.singletonList("example.com"));
        when(identityProviderProvisioning.retrieveAll(true, OriginKeys.UAA)).thenReturn(Collections.singletonList(oidcProvider));

        mockMvc.perform(post)
                .andExpect(view().name("accounts/new_activation_email"))
                .andExpect(model().attribute("error_message_code", "other_idp"));

        Mockito.verify(accountCreationService, times(0)).beginActivation("user1@example.com", "password", "app", "http://example.com/redirect");
    }

    @Test
    void sendActivationEmailWithUserNameConflict() throws Exception {
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
    void invalidPassword() throws Exception {
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
    void invalidEmail() throws Exception {
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
    void passwordMismatch() throws Exception {
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
    void verifyUser() throws Exception {
        when(accountCreationService.completeActivation("the_secret_code"))
                .thenReturn(new AccountCreationService.AccountCreationResponse("newly-created-user-id", "username", "user@example.com", "//example.com/callback"));

        MockHttpServletRequestBuilder get = get("/verify_user")
                .param("code", "the_secret_code");

        mockMvc.perform(get)
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/login?success=verify_success&form_redirect_uri=//example.com/callback"));

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    void verifyUserWithPriorHeadRequest() throws Exception {
        when(accountCreationService.completeActivation("the_secret_code"))
                .thenReturn(new AccountCreationService.AccountCreationResponse("newly-created-user-id", "username", "user@example.com", "//example.com/callback"));

        mockMvc.perform(head("/verify_user").param("code", "the_secret_code"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/login"));
        mockMvc.perform(get("/verify_user").param("code", "the_secret_code"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/login?success=verify_success&form_redirect_uri=//example.com/callback"));

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        Mockito.verify(accountCreationService, times(1)).completeActivation("the_secret_code");
    }

    @EnableWebMvc
    @Import(ThymeleafConfig.class)
    static class ContextConfiguration implements WebMvcConfigurer {

        @Autowired
        private RequestMappingHandlerAdapter requestMappingHandlerAdapter;

        @PostConstruct
        public void init() {
            requestMappingHandlerAdapter.setIgnoreDefaultModelOnRedirect(false);
        }

        @Override
        public void configureDefaultServletHandling(DefaultServletHandlerConfigurer configurer) {
            configurer.enable();
        }

        @Bean
        BuildInfo buildInfo() {
            return new TestBuildInfo();
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
