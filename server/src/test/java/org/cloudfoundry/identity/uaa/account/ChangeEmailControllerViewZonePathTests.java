package org.cloudfoundry.identity.uaa.account;

import jakarta.annotation.PostConstruct;
import org.cloudfoundry.identity.uaa.TestClassNullifier;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.home.BuildInfo;
import org.cloudfoundry.identity.uaa.login.ThymeleafConfig;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.util.ZoneRequestPathMode;
import org.cloudfoundry.identity.uaa.util.beans.TestBuildInfo;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
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
import org.cloudfoundry.identity.uaa.extensions.EnabledIfZonePathsEnabled;

import java.util.Collections;

import static org.hamcrest.CoreMatchers.containsString;
import static org.mockito.Mockito.mock;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * View tests for ChangeEmailController (change_email template). Each test is parameterized by
 * {@link ZoneRequestPathMode}. Asserts that the form action is zone-aware. ZONE_PATH will pass after implementation.
 */
@ExtendWith(PollutionPreventionExtension.class)
@WebAppConfiguration
@SpringJUnitConfig(classes = ChangeEmailControllerViewZonePathTests.ContextConfiguration.class)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
@EnabledIfZonePathsEnabled
class ChangeEmailControllerViewZonePathTests extends TestClassNullifier {

    /** Uses context path for ZONE_PATH so Thymeleaf generates correct form action URLs. */
    private static MockHttpServletRequestBuilder request(ZoneRequestPathMode mode, String pathSuffix) {
        if (mode.redirectPrefix().isEmpty()) {
            return get(pathSuffix);
        }
        String ctx = "/z/" + mode.getSubdomain();
        return get(ctx + pathSuffix).contextPath(ctx).servletPath(pathSuffix);
    }

    private static String expectedFormAction(ZoneRequestPathMode mode) {
        String path = "/change_email.do";
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

    private void setSecurityContextWithUaaUser(ZoneRequestPathMode mode) {
        if (mode == ZoneRequestPathMode.DEFAULT) {
            IdentityZoneHolder.set(IdentityZone.getUaa());
        } else {
            mode.setZone();
        }
        String zoneId = IdentityZoneHolder.get().getId();
        UaaAuthentication authentication = new UaaAuthentication(
                new UaaPrincipal("user-id-001", "bob", "user@example.com", OriginKeys.UAA, null, zoneId),
                Collections.singletonList(UaaAuthority.UAA_USER),
                null
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    @ParameterizedTest
    @EnumSource(ZoneRequestPathMode.class)
    void changeEmailPageContainsZoneAwareFormAction(ZoneRequestPathMode mode) throws Exception {
        setSecurityContextWithUaaUser(mode);
        mockMvc.perform(request(mode, "/change_email"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString(expectedFormAction(mode))));
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
        ChangeEmailService changeEmailService() {
            return mock(ChangeEmailService.class);
        }

        @Bean
        UaaUserDatabase uaaUserDatabase() {
            return mock(UaaUserDatabase.class);
        }

        @Bean
        ChangeEmailController changeEmailController(ChangeEmailService changeEmailService,
                                                   UaaUserDatabase uaaUserDatabase) {
            return new ChangeEmailController(changeEmailService, uaaUserDatabase);
        }
    }
}
