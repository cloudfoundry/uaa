package org.cloudfoundry.identity.uaa.account;

import jakarta.annotation.PostConstruct;
import org.cloudfoundry.identity.uaa.TestClassNullifier;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.home.BuildInfo;
import org.cloudfoundry.identity.uaa.login.ThymeleafConfig;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.util.ZoneRequestPathMode;
import org.cloudfoundry.identity.uaa.util.beans.TestBuildInfo;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.DefaultServletHandlerConfigurer;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerAdapter;
import org.cloudfoundry.identity.uaa.extensions.EnabledIfZonePathsEnabled;

import static org.hamcrest.CoreMatchers.containsString;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * View tests for AccountsController (accounts/email_sent, accounts/new_activation_email, accounts/link_prompt).
 * Each test is parameterized by {@link ZoneRequestPathMode}. Asserts that create_account and login links
 * (and form actions) are zone-aware. ZONE_PATH expectations will pass after implementation.
 */
@ExtendWith(PollutionPreventionExtension.class)
@WebAppConfiguration
@SpringJUnitConfig(classes = AccountsControllerViewZonePathTests.ContextConfiguration.class)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
@EnabledIfZonePathsEnabled
class AccountsControllerViewZonePathTests extends TestClassNullifier {

    /** Uses context path for ZONE_PATH so Thymeleaf sees request.getContextPath() and generates correct URLs. */
    private static MockHttpServletRequestBuilder request(ZoneRequestPathMode mode, String pathSuffix) {
        if (mode.redirectPrefix().isEmpty()) {
            return get(pathSuffix);
        }
        String ctx = "/z/" + mode.getSubdomain();
        return get(ctx + pathSuffix).contextPath(ctx).servletPath(pathSuffix);
    }

    private static String expectedHref(ZoneRequestPathMode mode, String path) {
        String prefix = mode.redirectPrefix();
        return prefix.isEmpty() ? "href=\"" + path + "\"" : "href=\"" + prefix + path + "\"";
    }

    private static String expectedAction(ZoneRequestPathMode mode, String path) {
        String prefix = mode.redirectPrefix();
        return prefix.isEmpty() ? "action=\"" + path + "\"" : "action=\"" + prefix + path + "\"";
    }

    @Autowired
    private WebApplicationContext webApplicationContext;

    private MockMvc mockMvc;

    @BeforeEach
    void beforeEach() {
        SecurityContextHolder.clearContext();
        IdentityZoneHolder.clear();
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).build();
    }

    @AfterEach
    void afterEach() {
        SecurityContextHolder.clearContext();
        IdentityZoneHolder.clear();
    }

    private void setZoneWithSelfServiceEnabled(ZoneRequestPathMode mode) {
        if (mode == ZoneRequestPathMode.DEFAULT) {
            IdentityZone zone = IdentityZone.getUaa();
            zone.getConfig().getLinks().getSelfService().setSelfServiceLinksEnabled(true);
            IdentityZoneHolder.set(zone);
        } else {
            mode.setZone();
            IdentityZoneHolder.get().getConfig().getLinks().getSelfService().setSelfServiceLinksEnabled(true);
        }
    }

    @ParameterizedTest
    @EnumSource(ZoneRequestPathMode.class)
    void accountsEmailSentPageContainsZoneAwareCreateAccountLink(ZoneRequestPathMode mode) throws Exception {
        setZoneWithSelfServiceEnabled(mode);
        mockMvc.perform(request(mode, "/accounts/email_sent"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString(expectedHref(mode, "/create_account"))));
    }

    @ParameterizedTest
    @EnumSource(ZoneRequestPathMode.class)
    void createAccountPageContainsZoneAwareFormActionAndLoginLink(ZoneRequestPathMode mode) throws Exception {
        setZoneWithSelfServiceEnabled(mode);
        mockMvc.perform(request(mode, "/create_account"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString(expectedAction(mode, "/create_account.do"))))
                .andExpect(content().string(containsString(expectedHref(mode, "/login"))));
    }

    @ParameterizedTest
    @EnumSource(ZoneRequestPathMode.class)
    void linkPromptPageContainsZoneAwareCreateAccountAndLoginLinks(ZoneRequestPathMode mode) throws Exception {
        setZoneWithSelfServiceEnabled(mode);
        mockMvc.perform(request(mode, "/verify_user").param("code", "expired-code"))
                .andExpect(status().is(HttpStatus.UNPROCESSABLE_ENTITY.value()))
                .andExpect(content().string(containsString(expectedHref(mode, "/create_account"))))
                .andExpect(content().string(containsString(expectedHref(mode, "/login"))));
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
            AccountCreationService accountCreationService = mock(AccountCreationService.class);
            when(accountCreationService.completeActivation(anyString()))
                    .thenThrow(new HttpClientErrorException(HttpStatus.GONE, "code expired"));
            return accountCreationService;
        }

        @Bean
        IdentityProviderProvisioning identityProviderProvisioning() {
            return mock(JdbcIdentityProviderProvisioning.class);
        }

        @Bean
        AccountsController accountsController(AccountCreationService accountCreationService,
                                             IdentityProviderProvisioning identityProviderProvisioning) {
            return new AccountsController(accountCreationService, identityProviderProvisioning);
        }
    }
}
