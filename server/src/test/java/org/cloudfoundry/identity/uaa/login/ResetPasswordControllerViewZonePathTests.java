package org.cloudfoundry.identity.uaa.login;

import jakarta.annotation.PostConstruct;
import org.cloudfoundry.identity.uaa.TestClassNullifier;
import org.cloudfoundry.identity.uaa.account.ResetPasswordController;
import org.cloudfoundry.identity.uaa.account.ResetPasswordService;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.codestore.InMemoryExpiringCodeStore;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.home.BuildInfo;
import org.cloudfoundry.identity.uaa.message.MessageService;
import org.cloudfoundry.identity.uaa.util.TimeServiceImpl;
import org.cloudfoundry.identity.uaa.util.ZoneRequestPathMode;
import org.cloudfoundry.identity.uaa.util.beans.TestBuildInfo;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManagerImpl;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.support.ResourceBundleMessageSource;
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
import org.thymeleaf.TemplateEngine;
import org.cloudfoundry.identity.uaa.extensions.EnabledIfZonePathsEnabled;

import static org.hamcrest.CoreMatchers.containsString;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * View tests for ResetPasswordController (email_sent template). Each test is parameterized by
 * {@link ZoneRequestPathMode}. Asserts that the "Back to Sign In" link is zone-aware:
 * href="/login" for DEFAULT, href="/z/test-zone/login" for ZONE_PATH (latter will pass after implementation).
 */
@ExtendWith(PollutionPreventionExtension.class)
@WebAppConfiguration
@SpringJUnitConfig(classes = ResetPasswordControllerViewZonePathTests.ContextConfiguration.class)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
@EnabledIfZonePathsEnabled
class ResetPasswordControllerViewZonePathTests extends TestClassNullifier {

    /** Uses context path for ZONE_PATH so Thymeleaf generates correct link URLs. */
    private static MockHttpServletRequestBuilder request(ZoneRequestPathMode mode, String pathSuffix) {
        if (mode.redirectPrefix().isEmpty()) {
            return get(pathSuffix);
        }
        String ctx = "/z/" + mode.getSubdomain();
        return get(ctx + pathSuffix).contextPath(ctx).servletPath(pathSuffix);
    }

    /** Expected "Back to Sign In" link: href="/login" or href="/z/test-zone/login". */
    private static String expectedLoginHref(ZoneRequestPathMode mode) {
        String path = "/login";
        String prefix = mode.redirectPrefix();
        return prefix.isEmpty() ? "href=\"" + path + "\"" : "href=\"" + prefix + path + "\"";
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

    @ParameterizedTest
    @EnumSource(ZoneRequestPathMode.class)
    void emailSentPageContainsZoneAwareBackToSignInLink(ZoneRequestPathMode mode) throws Exception {
        if (mode == ZoneRequestPathMode.DEFAULT) {
            IdentityZoneHolder.set(IdentityZone.getUaa());
        } else {
            mode.setZone();
        }
        mockMvc.perform(request(mode, "/email_sent").param("code", "reset_password"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString(expectedLoginHref(mode))));
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
        public ResetPasswordService resetPasswordService() {
            return mock(ResetPasswordService.class);
        }

        @Bean
        public MessageService messageService() {
            return mock(MessageService.class);
        }

        @Bean
        public ExpiringCodeStore codeStore() {
            return new InMemoryExpiringCodeStore(new TimeServiceImpl());
        }

        @Bean
        public UaaUserDatabase userDatabase() {
            UaaUserDatabase userDatabase = mock(UaaUserDatabase.class);
            when(userDatabase.retrieveUserById(anyString())).thenReturn(new UaaUser("username", "password", "email", "givenname", "familyname"));
            return userDatabase;
        }

        @Bean
        ResetPasswordController resetPasswordController(ResetPasswordService resetPasswordService,
                                                       MessageService messageService,
                                                       @Qualifier("mailTemplateEngine") TemplateEngine mailTemplateEngine,
                                                       ExpiringCodeStore codeStore,
                                                       UaaUserDatabase userDatabase) {
            return new ResetPasswordController(
                    new IdentityZoneManagerImpl(),
                    resetPasswordService,
                    messageService,
                    mailTemplateEngine,
                    codeStore,
                    userDatabase,
                    "http://localhost");
        }
    }
}
