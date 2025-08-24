package org.cloudfoundry.identity.uaa.scim.beans;

import org.cloudfoundry.identity.uaa.oauth.UaaTokenServices;
import org.cloudfoundry.identity.uaa.oauth.provider.authentication.OAuth2AuthenticationManager;
import org.cloudfoundry.identity.uaa.oauth.provider.authentication.OAuth2AuthenticationProcessingFilter;
import org.cloudfoundry.identity.uaa.oauth.provider.error.OAuth2AccessDeniedHandler;
import org.cloudfoundry.identity.uaa.oauth.provider.error.OAuth2AuthenticationEntryPoint;
import org.cloudfoundry.identity.uaa.security.IsSelfCheck;
import org.cloudfoundry.identity.uaa.web.SelfCheckAuthorizationManager;
import org.cloudfoundry.identity.uaa.security.web.CookieBasedCsrfTokenRepository;
import org.cloudfoundry.identity.uaa.web.FilterChainOrder;
import org.cloudfoundry.identity.uaa.web.UaaFilterChain;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AnonymousConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import static org.cloudfoundry.identity.uaa.web.AuthorizationManagersUtils.anyOf;

@Configuration
@EnableWebSecurity
class ScimSecurityConfiguration {

    @Autowired
    @Qualifier("tokenServices")
    private UaaTokenServices tokenServices;

    @Autowired
    @Qualifier("oauthAuthenticationEntryPoint")
    OAuth2AuthenticationEntryPoint oauthAuthenticationEntryPoint;

    @Autowired
    @Qualifier("oauthAccessDeniedHandler")
    OAuth2AccessDeniedHandler oauthAccessDeniedHandler;

    @Autowired
    CookieBasedCsrfTokenRepository csrfTokenRepository;

    @Bean
    @Order(FilterChainOrder.SCIM_PASSWORD)
    UaaFilterChain scimUserPassword(HttpSecurity http) throws Exception {
        SecurityFilterChain chain = http
                .securityMatcher("/Users/*/password", "/Users/*/password/**")
                .authorizeHttpRequests( auth -> {
                    auth.requestMatchers("/**").access(anyOf(true).hasScope("password.write"));
                    auth.anyRequest().denyAll();
                })
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(passwordResourceAuthenticationFilter().getFilter(), BasicAuthenticationFilter.class)
                .anonymous(AnonymousConfigurer::disable)
                .csrf(CsrfConfigurer::disable)
                .exceptionHandling(exception ->
                        exception.authenticationEntryPoint(oauthAuthenticationEntryPoint)
                                .accessDeniedHandler(oauthAccessDeniedHandler)
                )
                .securityContext(sc -> sc.requireExplicitSave(false))
                .build();

        return new UaaFilterChain(chain, "scimUserPassword");
    }

    @Bean
    @Order(FilterChainOrder.SCIM)
    UaaFilterChain scimUserIds(HttpSecurity http) throws Exception {
        SecurityFilterChain chain = http
                .securityMatcher("/ids/Users", "/ids/Users*", "/ids/Users/**")
                .authorizeHttpRequests( auth -> {
                    auth.requestMatchers("/**").access(anyOf(true).hasScope("scim.userids"));
                    auth.anyRequest().denyAll();
                })
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(resourceAgnosticAuthenticationFilter().getFilter(), BasicAuthenticationFilter.class)
                .anonymous(AnonymousConfigurer::disable)
                .csrf(CsrfConfigurer::disable)
                .exceptionHandling(exception ->
                        exception.authenticationEntryPoint(oauthAuthenticationEntryPoint)
                                .accessDeniedHandler(oauthAccessDeniedHandler)
                )
                .securityContext(sc -> sc.requireExplicitSave(false))
                .build();

        return new UaaFilterChain(chain, "scimUserIds");
    }

    @Bean
    @Order(FilterChainOrder.SCIM)
    UaaFilterChain groupEndpointSecurity(HttpSecurity http) throws Exception {
        SecurityFilterChain chain = http
                .securityMatcher("/Groups", "/Groups/**")
                .authorizeHttpRequests( auth -> {
                    auth.requestMatchers("/Groups/zones").access(anyOf(true).hasScope("scim.zones"));
                    auth.requestMatchers("/Groups/zones/**").access(anyOf(true).hasScope("scim.zones"));
                    auth.requestMatchers(HttpMethod.GET, "/Groups/External").access(anyOf(true).hasScope("scim.read").isZoneAdmin());
                    auth.requestMatchers(HttpMethod.POST, "/Groups/External").access(anyOf(true).hasScope("scim.write").isZoneAdmin());
                    auth.requestMatchers(HttpMethod.DELETE, "/Groups/**").access(anyOf(true).hasScope("scim.write").isZoneAdmin());
                    auth.requestMatchers(HttpMethod.PUT, "/Groups/**").access(anyOf(true).hasScope("scim.write", "groups.update").isZoneAdmin());
                    auth.requestMatchers(HttpMethod.POST, "/Groups/**").access(anyOf(true).hasScope("scim.write", "groups.update").isZoneAdmin());
                    auth.requestMatchers(HttpMethod.GET, "/Groups/**").access(anyOf(true).hasScope("scim.read").isZoneAdmin());
                    auth.requestMatchers(HttpMethod.PATCH, "/Groups/**").access(anyOf(true).hasScope("scim.write", "groups.update").isZoneAdmin());
                    auth.requestMatchers(HttpMethod.POST, "/Groups").access(anyOf(true).hasScope("scim.write").isZoneAdmin());
                    auth.anyRequest().denyAll();
                })
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(resourceAgnosticAuthenticationFilter().getFilter(), BasicAuthenticationFilter.class)
                .anonymous(AnonymousConfigurer::disable)
                .csrf(CsrfConfigurer::disable)
                .exceptionHandling(exception ->
                        exception.authenticationEntryPoint(oauthAuthenticationEntryPoint)
                                .accessDeniedHandler(oauthAccessDeniedHandler)
                )
                .securityContext(sc -> sc.requireExplicitSave(false))
                .build();

        return new UaaFilterChain(chain, "groupEndpointSecurity");
    }

    @Bean
    @Order(FilterChainOrder.SCIM)
    UaaFilterChain scimUsers(HttpSecurity http, @Qualifier("self") IsSelfCheck selfCheck) throws Exception {
        SecurityFilterChain chain = http
                .securityMatcher("/Users", "/Users/**")
                .authorizeHttpRequests( auth -> {
                    auth.requestMatchers(HttpMethod.GET, "/Users/*/verify-link").access(anyOf(true).hasScope("scim.create").isZoneAdmin());
                    auth.requestMatchers(HttpMethod.GET, "/Users/*/verify").access(anyOf(true).hasScope("scim.write", "scim.create").isZoneAdmin());
                    auth.requestMatchers(HttpMethod.PATCH, "/Users/*/status").access(anyOf(true).hasScope("scim.write", "uaa.account_status.write").isZoneAdmin());
                    auth.requestMatchers(HttpMethod.GET, "/Users/**").access(anyOf(true).hasScope("scim.read").or(SelfCheckAuthorizationManager.isUserSelf(selfCheck, 1)).isZoneAdmin());
                    auth.requestMatchers(HttpMethod.DELETE, "/Users","/Users/*").access(anyOf(true).hasScope("scim.write").isZoneAdmin());
                    auth.requestMatchers(HttpMethod.PUT, "/Users","/Users/*").access(anyOf(true).hasScope("scim.write").or(SelfCheckAuthorizationManager.isUserSelf(selfCheck, 1)).isZoneAdmin());
                    auth.requestMatchers(HttpMethod.PATCH, "/Users","/Users/*").access(anyOf(true).hasScope("scim.write").or(SelfCheckAuthorizationManager.isUserSelf(selfCheck, 1)).isZoneAdmin());
                    auth.requestMatchers(HttpMethod.POST, "/Users","/Users/*").access(anyOf(true).hasScope("scim.write", "scim.create").isZoneAdmin());
                    auth.anyRequest().denyAll();
                })
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(resourceAgnosticAuthenticationFilter().getFilter(), BasicAuthenticationFilter.class)
                .anonymous(AnonymousConfigurer::disable)
                .csrf(CsrfConfigurer::disable)
                .exceptionHandling(exception ->
                        exception.authenticationEntryPoint(oauthAuthenticationEntryPoint)
                                .accessDeniedHandler(oauthAccessDeniedHandler)
                )
                .securityContext(sc -> sc.requireExplicitSave(false))
                .build();

        return new UaaFilterChain(chain, "scimUsers");
    }

    @Bean
    FilterRegistrationBean<OAuth2AuthenticationProcessingFilter> passwordResourceAuthenticationFilter() {
        OAuth2AuthenticationProcessingFilter filter = new OAuth2AuthenticationProcessingFilter();
        filter.setAuthenticationManager(getoAuth2AuthenticationManager(tokenServices, "password"));
        filter.setAuthenticationEntryPoint(oauthAuthenticationEntryPoint);
        FilterRegistrationBean<OAuth2AuthenticationProcessingFilter> bean = new FilterRegistrationBean<>(filter);
        bean.setEnabled(false);
        return bean;
    }

    @Bean
    FilterRegistrationBean<OAuth2AuthenticationProcessingFilter> scimResourceAuthenticationFilter() {
        OAuth2AuthenticationProcessingFilter filter = new OAuth2AuthenticationProcessingFilter();
        filter.setAuthenticationManager(getoAuth2AuthenticationManager(tokenServices, "scim"));
        filter.setAuthenticationEntryPoint(oauthAuthenticationEntryPoint);
        FilterRegistrationBean<OAuth2AuthenticationProcessingFilter> bean = new FilterRegistrationBean<>(filter);
        bean.setEnabled(false);
        return bean;
    }

    @Bean
    FilterRegistrationBean<OAuth2AuthenticationProcessingFilter> resourceAgnosticAuthenticationFilter() {
        OAuth2AuthenticationProcessingFilter filter = new OAuth2AuthenticationProcessingFilter();
        filter.setAuthenticationManager(getoAuth2AuthenticationManager(tokenServices, null));
        filter.setAuthenticationEntryPoint(oauthAuthenticationEntryPoint);
        FilterRegistrationBean<OAuth2AuthenticationProcessingFilter> bean = new FilterRegistrationBean<>(filter);
        bean.setEnabled(false);
        return bean;
    }


    private static OAuth2AuthenticationManager getoAuth2AuthenticationManager(
            UaaTokenServices tokenServices,
            String resourceId
    ) {
        OAuth2AuthenticationManager authenticationManager = new OAuth2AuthenticationManager();
        authenticationManager.setTokenServices(tokenServices);
        authenticationManager.setResourceId(resourceId);
        return authenticationManager;
    }


}
