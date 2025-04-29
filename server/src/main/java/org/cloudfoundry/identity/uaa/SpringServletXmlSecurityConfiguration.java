package org.cloudfoundry.identity.uaa;

import org.cloudfoundry.identity.uaa.oauth.provider.authentication.OAuth2AuthenticationProcessingFilter;
import org.cloudfoundry.identity.uaa.scim.DisableUserManagementSecurityFilter;
import org.cloudfoundry.identity.uaa.security.web.SecurityFilterChainPostProcessor;
import org.cloudfoundry.identity.uaa.web.BackwardsCompatibleScopeParsingFilter;
import org.cloudfoundry.identity.uaa.web.FilterChainOrder;
import org.cloudfoundry.identity.uaa.web.UaaFilterChain;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AnonymousConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2LogoutRequestFilter;
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2LogoutResponseFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.servlet.config.annotation.DefaultServletHandlerConfigurer;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import javax.servlet.Filter;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

@Configuration
@EnableWebSecurity
@EnableWebMvc
public class SpringServletXmlSecurityConfiguration implements WebMvcConfigurer {

    @Override
    public void configureDefaultServletHandling(DefaultServletHandlerConfigurer configurer) {
        configurer.enable();
    }

    @Bean
    @Order(FilterChainOrder.NO_SECURITY)
    UaaFilterChain secFilterOpen05Healthz(HttpSecurity http) throws Exception {
        SecurityFilterChain chain = http
                .securityMatcher("/healthz/**")
                .authorizeHttpRequests().anyRequest().permitAll().and()
                .anonymous(AnonymousConfigurer::disable)
                .csrf(CsrfConfigurer::disable)
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .build();

        return new UaaFilterChain(chain, "secFilterOpen05Healthz");
    }

    @Bean
    @Order(FilterChainOrder.NO_SECURITY)
    UaaFilterChain secFilterOpen06SAMLMetadata(HttpSecurity http) throws Exception {
        SecurityFilterChain chain = http
                .securityMatcher("/saml/metadata/**")
                .authorizeHttpRequests().anyRequest().permitAll().and()
                .anonymous(AnonymousConfigurer::disable)
                .csrf(CsrfConfigurer::disable)
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .build();

        return new UaaFilterChain(chain, "secFilterOpen06SAMLMetadata");
    }

    @Bean
    @Order(FilterChainOrder.NO_SECURITY)
    UaaFilterChain noSecurityFilters(HttpSecurity http) throws Exception {
        SecurityFilterChain chain = http
                .securityMatcher(
                        "/error**",
                        "/error/**",
                        "/resources/**",
                        "/square-logo.png",
                        "/info",
                        "/password/**",
                        "/saml/web/**",
                        "/vendor/**",
                        "/email_sent",
                        "/accounts/email_sent",
                        "/invalid_request",
                        "/saml_error",
                        "/favicon.ico",
                        "/oauth_error",
                        "/session",
                        "/session_management",
                        "/oauth/token/.well-known/openid-configuration",
                        "/.well-known/openid-configuration"
                )
                .authorizeHttpRequests().anyRequest().permitAll().and()
                .anonymous(AnonymousConfigurer::disable)
                .csrf(CsrfConfigurer::disable)
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .build();

        return new UaaFilterChain(chain, "noSecurityFilters");
    }

    @Bean
    SecurityFilterChainPostProcessor securityFilterChainPostProcessor(
            UaaProperties.RootLevel rootLevel,
            @Qualifier("tracingFilter") Filter tracingFilter,
            @Qualifier("metricsFilter") Filter metricsFilter,
            @Qualifier("headerFilter") Filter headerFilter,
            @Qualifier("contentSecurityPolicyFilter") Filter contentSecurityPolicyFilter,
            @Qualifier("utf8ConversionFilter") Filter utf8ConversionFilter,
            @Qualifier("limitedModeUaaFilter") Filter limitedModeUaaFilter,
            @Qualifier("identityZoneResolvingFilter") Filter identityZoneResolvingFilter,
            @Qualifier("corsFilter") Filter corsFilter,
            @Qualifier("disableIdTokenResponseFilter") Filter disableIdTokenResponseFilter,
            @Qualifier("saml2WebSsoAuthenticationRequestFilter") Filter saml2WebSsoAuthenticationRequestFilter,
            @Qualifier("saml2WebSsoAuthenticationFilter") Filter saml2WebSsoAuthenticationFilter,
            @Qualifier("identityZoneSwitchingFilter") Filter identityZoneSwitchingFilter,
            @Qualifier("saml2LogoutRequestFilter") Filter saml2LogoutRequestFilter,
            @Qualifier("saml2LogoutResponseFilter") Filter saml2LogoutResponseFilter,
            @Qualifier("userManagementSecurityFilter") Filter userManagementSecurityFilter,
            @Qualifier("userManagementFilter") Filter userManagementFilter,
            @Qualifier("sessionResetFilter") Filter sessionResetFilter
            ) {
        SecurityFilterChainPostProcessor bean = new SecurityFilterChainPostProcessor();
        bean.setDumpRequests(rootLevel.dump_requests());
        bean.setRequireHttps(rootLevel.require_https());
        bean.setHttpsPort(rootLevel.https_port());

        Map<Class<? extends Exception>, SecurityFilterChainPostProcessor.ReasonPhrase> errorMap = new HashMap<>();
        errorMap.put(org.springframework.dao.NonTransientDataAccessException .class, new SecurityFilterChainPostProcessor.ReasonPhrase(503, "Database unavailable. Retry later."));
        bean.setErrorMap(errorMap);

        //TODO
        bean.setRedirectToHttps(Arrays.asList("uiSecurity", "secFilterOpen06SAMLMetadata"));
        bean.setIgnore(Arrays.asList("secFilterOpen05Healthz"));

        Map<SecurityFilterChainPostProcessor.FilterPosition, Filter> additionalFilters = new LinkedHashMap<>();
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.position(0), tracingFilter);
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.position(1), metricsFilter);
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.position(2), headerFilter);
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.position(3), new BackwardsCompatibleScopeParsingFilter());
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.position(4), contentSecurityPolicyFilter);
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.position(5), utf8ConversionFilter);
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.position(6), limitedModeUaaFilter);
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.position(7), identityZoneResolvingFilter);
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.position(8), corsFilter);
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.position(9), disableIdTokenResponseFilter);
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.position(10), saml2WebSsoAuthenticationRequestFilter);
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.position(11), saml2WebSsoAuthenticationFilter);
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.after(OAuth2AuthenticationProcessingFilter.class), identityZoneSwitchingFilter);
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.after(IdentityZoneSwitchingFilter.class), saml2LogoutRequestFilter);
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.after(Saml2LogoutRequestFilter.class), saml2LogoutResponseFilter);
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.after(Saml2LogoutResponseFilter.class), userManagementSecurityFilter);
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.after(DisableUserManagementSecurityFilter.class), userManagementFilter);
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.position(102), sessionResetFilter);

        bean.setAdditionalFilters(additionalFilters);

        return bean;
    }
}
