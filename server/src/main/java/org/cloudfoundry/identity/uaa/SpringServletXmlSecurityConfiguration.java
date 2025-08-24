package org.cloudfoundry.identity.uaa;

import jakarta.servlet.Filter;
import org.apache.catalina.filters.HttpHeaderSecurityFilter;
import org.cloudfoundry.identity.uaa.authentication.SessionResetFilter;
import org.cloudfoundry.identity.uaa.authentication.UTF8ConversionFilter;
import org.cloudfoundry.identity.uaa.metrics.UaaMetricsFilter;
import org.cloudfoundry.identity.uaa.oauth.DisableIdTokenResponseTypeFilter;
import org.cloudfoundry.identity.uaa.oauth.provider.authentication.OAuth2AuthenticationProcessingFilter;
import org.cloudfoundry.identity.uaa.ratelimiting.RateLimitingFilter;
import org.cloudfoundry.identity.uaa.scim.DisableInternalUserManagementFilter;
import org.cloudfoundry.identity.uaa.scim.DisableUserManagementSecurityFilter;
import org.cloudfoundry.identity.uaa.security.web.ContentSecurityPolicyFilter;
import org.cloudfoundry.identity.uaa.security.web.CorsFilter;
import org.cloudfoundry.identity.uaa.security.web.SecurityFilterChainPostProcessor;
import org.cloudfoundry.identity.uaa.web.BackwardsCompatibleScopeParsingFilter;
import org.cloudfoundry.identity.uaa.web.FilterChainOrder;
import org.cloudfoundry.identity.uaa.web.HeaderFilter;
import org.cloudfoundry.identity.uaa.web.LimitedModeUaaFilter;
import org.cloudfoundry.identity.uaa.web.UaaFilterChain;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneResolvingFilter;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AnonymousConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2LogoutRequestFilter;
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2LogoutResponseFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.filter.RequestContextFilter;

import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
public class SpringServletXmlSecurityConfiguration {

    private final String[] noSecurityEndpoints = {
            "/error**",
            "/error/**",
            "/rejected",
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
    };

    private final String[] secFilterOpenSamlEndPoints = {
            "/saml/metadata/**",
            "/saml/metadata"
    };

    private final String[] secFilterOpenHealthzEndPoints = {
            "/healthz/**"
    };

    @Bean
    @Order(FilterChainOrder.NO_SECURITY)
    UaaFilterChain secFilterOpen05Healthz(HttpSecurity http) throws Exception {
        SecurityFilterChain chain = http
                .securityMatcher(secFilterOpenHealthzEndPoints)
                .authorizeHttpRequests(requests -> requests.anyRequest().permitAll())
                .anonymous(AnonymousConfigurer::disable)
                .csrf(csrf -> csrf.ignoringRequestMatchers(secFilterOpenHealthzEndPoints))
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
                .securityMatcher(secFilterOpenSamlEndPoints)
                .authorizeHttpRequests(requests -> requests.anyRequest().permitAll())
                .anonymous(AnonymousConfigurer::disable)
                .csrf(csrf -> csrf.ignoringRequestMatchers(secFilterOpenSamlEndPoints))
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .securityContext(sc -> sc.requireExplicitSave(false))
                .build();

        return new UaaFilterChain(chain, "secFilterOpen06SAMLMetadata");
    }

    @Bean
    @Order(FilterChainOrder.NO_SECURITY)
    UaaFilterChain noSecurityFilters(HttpSecurity http) throws Exception {
        SecurityFilterChain chain = http
                .headers(headers -> headers.frameOptions(withDefaults()))
                .securityMatcher(noSecurityEndpoints)
                .authorizeHttpRequests(requests -> requests.anyRequest().permitAll())
                .anonymous(AnonymousConfigurer::disable)
                .csrf(csrf -> csrf.ignoringRequestMatchers(noSecurityEndpoints))
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .securityContext(sc -> sc.requireExplicitSave(false))
                .build();

        return new UaaFilterChain(chain, "noSecurityFilters");
    }

    @Bean
    SecurityFilterChainPostProcessor securityFilterChainPostProcessor(
            UaaProperties.RootLevel rootLevel,
            @Qualifier("tracingFilter") FilterRegistrationBean<Filter> tracingFilter,
            @Qualifier("metricsFilter") FilterRegistrationBean<UaaMetricsFilter> metricsFilter,
            @Qualifier("headerFilter") FilterRegistrationBean<HeaderFilter> headerFilter,
            @Qualifier("contentSecurityPolicyFilter") FilterRegistrationBean<ContentSecurityPolicyFilter> contentSecurityPolicyFilter,
            @Qualifier("limitedModeUaaFilter") FilterRegistrationBean<LimitedModeUaaFilter> limitedModeUaaFilter,
            @Qualifier("identityZoneResolvingFilter") FilterRegistrationBean<IdentityZoneResolvingFilter> identityZoneResolvingFilter,
            @Qualifier("corsFilter") FilterRegistrationBean<CorsFilter> corsFilter,
            @Qualifier("disableIdTokenResponseFilter") FilterRegistrationBean<DisableIdTokenResponseTypeFilter> disableIdTokenResponseFilter,
            @Qualifier("saml2WebSsoAuthenticationRequestFilter") FilterRegistrationBean<Filter> saml2WebSsoAuthenticationRequestFilter,
            @Qualifier("saml2WebSsoAuthenticationFilter") FilterRegistrationBean<Filter> saml2WebSsoAuthenticationFilter,
            @Qualifier("identityZoneSwitchingFilter") FilterRegistrationBean<IdentityZoneSwitchingFilter> identityZoneSwitchingFilter,
            @Qualifier("saml2LogoutRequestFilter") FilterRegistrationBean<Saml2LogoutRequestFilter> saml2LogoutRequestFilter,
            @Qualifier("saml2LogoutResponseFilter") FilterRegistrationBean<Saml2LogoutResponseFilter> saml2LogoutResponseFilter,
            @Qualifier("userManagementSecurityFilter") FilterRegistrationBean<DisableUserManagementSecurityFilter> userManagementSecurityFilter,
            @Qualifier("userManagementFilter") FilterRegistrationBean<DisableInternalUserManagementFilter> userManagementFilter,
            @Qualifier("sessionResetFilter") FilterRegistrationBean<SessionResetFilter> sessionResetFilter,
            @Qualifier("httpHeaderSecurityFilter") FilterRegistrationBean<HttpHeaderSecurityFilter> httpHeaderSecurityFilter,
            @Qualifier("springRequestContextFilter") FilterRegistrationBean<RequestContextFilter> springRequestContextFilter,
            @Qualifier("rateLimitingFilter") FilterRegistrationBean<RateLimitingFilter> rateLimitingFilter
    ) {
        Filter utf8ConversionFilter = new UTF8ConversionFilter();

        SecurityFilterChainPostProcessor bean = new SecurityFilterChainPostProcessor();
        bean.setDumpRequests(rootLevel.dump_requests());
        bean.setRequireHttps(rootLevel.require_https());
        bean.setHttpsPort(rootLevel.https_port());

        Map<Class<? extends Exception>, SecurityFilterChainPostProcessor.ReasonPhrase> errorMap = new HashMap<>();
        errorMap.put(org.springframework.dao.NonTransientDataAccessException.class, new SecurityFilterChainPostProcessor.ReasonPhrase(503, "Database unavailable. Retry later."));
        bean.setErrorMap(errorMap);

        //TODO
        bean.setRedirectToHttps(Arrays.asList("uiSecurity", "secFilterOpen06SAMLMetadata"));
        bean.setIgnore(Arrays.asList("secFilterOpen05Healthz"));
        int filterPos = 0;
        Map<SecurityFilterChainPostProcessor.FilterPosition, Filter> additionalFilters = new LinkedHashMap<>();
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.position(filterPos++), rateLimitingFilter.getFilter());
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.position(filterPos++), springRequestContextFilter.getFilter());
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.position(filterPos++), httpHeaderSecurityFilter.getFilter());
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.position(filterPos++), tracingFilter.getFilter());
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.position(filterPos++), metricsFilter.getFilter());
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.position(filterPos++), headerFilter.getFilter());
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.position(filterPos++), new BackwardsCompatibleScopeParsingFilter());
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.position(filterPos++), contentSecurityPolicyFilter.getFilter());
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.position(filterPos++), utf8ConversionFilter);
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.position(filterPos++), limitedModeUaaFilter.getFilter());
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.position(filterPos++), identityZoneResolvingFilter.getFilter());
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.position(filterPos++), corsFilter.getFilter());
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.position(filterPos++), disableIdTokenResponseFilter.getFilter());
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.position(filterPos++), saml2WebSsoAuthenticationRequestFilter.getFilter());
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.position(filterPos++), saml2WebSsoAuthenticationFilter.getFilter());
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.after(OAuth2AuthenticationProcessingFilter.class), identityZoneSwitchingFilter.getFilter());
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.after(IdentityZoneSwitchingFilter.class), saml2LogoutRequestFilter.getFilter());
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.after(Saml2LogoutRequestFilter.class), saml2LogoutResponseFilter.getFilter());
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.after(Saml2LogoutResponseFilter.class), userManagementSecurityFilter.getFilter());
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.after(DisableUserManagementSecurityFilter.class), userManagementFilter.getFilter());
        additionalFilters.put(SecurityFilterChainPostProcessor.FilterPosition.position(102), sessionResetFilter.getFilter());

        bean.setAdditionalFilters(additionalFilters);

        return bean;
    }
}
