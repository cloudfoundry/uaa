/*
 *  ****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2025] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 *  ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.oauth.beans;

import org.cloudfoundry.identity.uaa.authentication.AuthzAuthenticationFilter;
import org.cloudfoundry.identity.uaa.authentication.BackwardsCompatibleTokenEndpointAuthenticationFilter;
import org.cloudfoundry.identity.uaa.authentication.ClientBasicAuthenticationFilter;
import org.cloudfoundry.identity.uaa.authentication.ClientParametersAuthenticationFilter;
import org.cloudfoundry.identity.uaa.authentication.CurrentUserCookieRequestFilter;
import org.cloudfoundry.identity.uaa.authentication.PasscodeAuthenticationFilter;
import org.cloudfoundry.identity.uaa.authentication.PasswordChangeRequiredFilter;
import org.cloudfoundry.identity.uaa.authentication.manager.DynamicZoneAwareAuthenticationManager;
import org.cloudfoundry.identity.uaa.oauth.HybridTokenGranterForAuthorizationCode;
import org.cloudfoundry.identity.uaa.oauth.UaaAuthorizationEndpoint;
import org.cloudfoundry.identity.uaa.oauth.UaaAuthorizationRequestManager;
import org.cloudfoundry.identity.uaa.oauth.UaaOauth2RequestValidator;
import org.cloudfoundry.identity.uaa.oauth.UaaTokenServices;
import org.cloudfoundry.identity.uaa.oauth.UserManagedAuthzApprovalHandler;
import org.cloudfoundry.identity.uaa.oauth.pkce.PkceValidationService;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2RequestFactory;
import org.cloudfoundry.identity.uaa.oauth.provider.TokenGranter;
import org.cloudfoundry.identity.uaa.oauth.provider.authentication.OAuth2AuthenticationProcessingFilter;
import org.cloudfoundry.identity.uaa.oauth.provider.code.AuthorizationCodeServices;
import org.cloudfoundry.identity.uaa.oauth.provider.endpoint.RedirectResolver;
import org.cloudfoundry.identity.uaa.oauth.provider.error.OAuth2AccessDeniedHandler;
import org.cloudfoundry.identity.uaa.oauth.provider.error.OAuth2AuthenticationEntryPoint;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.oauth.ExternalOAuthAuthenticationFilter;
import org.cloudfoundry.identity.uaa.security.IsSelfCheck;
import org.cloudfoundry.identity.uaa.security.web.UaaRequestMatcher;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.util.CachingPasswordEncoder;
import org.cloudfoundry.identity.uaa.web.FilterChainOrder;
import org.cloudfoundry.identity.uaa.web.SelfCheckAuthorizationManager;
import org.cloudfoundry.identity.uaa.web.UaaFilterChain;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.MultitenantJdbcClientDetailsService;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AnonymousConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import static org.cloudfoundry.identity.uaa.web.AuthorizationManagersUtils.anyOf;

@Configuration
@EnableWebSecurity
class OauthEndpointSecurityConfiguration {

    @Autowired
    @Qualifier("oauthAuthenticationEntryPoint")
    OAuth2AuthenticationEntryPoint oauthAuthenticationEntryPoint;

    @Autowired
    @Qualifier("basicAuthenticationEntryPoint")
    AuthenticationEntryPoint basicAuthenticationEntryPoint;

    @Autowired
    @Qualifier("oauthAccessDeniedHandler")
    OAuth2AccessDeniedHandler oauthAccessDeniedHandler;

    @Autowired
    @Qualifier("resourceAgnosticAuthenticationFilter")
    FilterRegistrationBean<OAuth2AuthenticationProcessingFilter> resourceAgnosticAuthenticationFilter;

    @Autowired
    @Qualifier("jdbcClientDetailsService")
    MultitenantJdbcClientDetailsService jdbcClientDetailsService;

    @Autowired
    @Qualifier("userDatabase")
    UaaUserDatabase userDatabase;

    @Autowired
    @Qualifier("cachingPasswordEncoder")
    CachingPasswordEncoder cachingPasswordEncoder;

    @Autowired
    @Qualifier("passcodeTokenMatcher")
    UaaRequestMatcher passcodeTokenMatcher;

    @Autowired
    @Qualifier("clientAuthenticationFilter")
    FilterRegistrationBean<ClientBasicAuthenticationFilter> clientAuthenticationFilter;

    @Autowired
    @Qualifier("passcodeAuthenticationFilter")
    FilterRegistrationBean<PasscodeAuthenticationFilter> passcodeAuthenticationFilter;

    @Autowired
    @Qualifier("oauthTokenApiRequestMatcher")
    UaaRequestMatcher oauthTokenApiRequestMatcher;

    @Autowired
    @Qualifier("tokenEndpointAuthenticationFilter")
    FilterRegistrationBean<BackwardsCompatibleTokenEndpointAuthenticationFilter> tokenEndpointAuthenticationFilter;

    @Autowired
    @Qualifier("clientAuthenticationManager")
    AuthenticationManager clientAuthenticationManager;

    @Autowired
    FilterRegistrationBean<AuthzAuthenticationFilter> authzAuthenticationFilter;

    @Autowired
    @Qualifier("oauthAuthorizeRequestMatcher")
    UaaRequestMatcher oauthAuthorizeRequestMatcher;

    @Autowired
    @Qualifier("zoneAwareAuthzAuthenticationManager")
    DynamicZoneAwareAuthenticationManager zoneAwareAuthzAuthenticationManager;

    @Autowired
    @Qualifier("oauthAuthorizeApiRequestMatcher")
    UaaRequestMatcher oauthAuthorizeApiRequestMatcher;

    @Autowired
    @Qualifier("promptOauthAuthorizeApiRequestMatcher")
    UaaRequestMatcher promptOauthAuthorizeApiRequestMatcher;

    @Autowired
    @Qualifier("passwordChangeRequiredFilter")
    FilterRegistrationBean<PasswordChangeRequiredFilter> passwordChangeRequiredFilter;

    @Autowired
    @Qualifier("currentUserCookieFilter")
    FilterRegistrationBean<CurrentUserCookieRequestFilter> currentUserCookieFilter;

    @Autowired
    @Qualifier("oauthAuthorizeRequestMatcherOld")
    UaaRequestMatcher oauthAuthorizeRequestMatcherOld;

    @Autowired
    @Qualifier("externalOAuthCallbackRequestMatcher")
    UaaRequestMatcher externalOAuthCallbackRequestMatcher;

    @Autowired
    @Qualifier("externalOAuthCallbackAuthenticationFilter")
    FilterRegistrationBean<ExternalOAuthAuthenticationFilter> externalOAuthCallbackAuthenticationFilter;

    @Autowired
    @Qualifier("loginEntryPoint")
    AuthenticationEntryPoint loginEntryPoint;

    @Autowired
    @Qualifier("userManagedApprovalHandler")
    UserManagedAuthzApprovalHandler userManagedApprovalHandler;

    @Autowired
    @Qualifier("authorizationRequestManager")
    UaaAuthorizationRequestManager authorizationRequestManager;

    @Autowired
    @Qualifier("tokenServices")
    UaaTokenServices tokenServices;

    @Autowired
    @Qualifier("identityProviderProvisioning")
    IdentityProviderProvisioning providerProvisioning;

    @Autowired
    @Qualifier("identityZoneManager")
    IdentityZoneManager identityZoneManager;

    @Autowired
    @Qualifier("oauth2RequestValidator")
    UaaOauth2RequestValidator oauth2RequestValidator;

    @Autowired
    RedirectResolver redirectResolver;

    @Autowired
    @Qualifier("authorizationCodeServices") AuthorizationCodeServices authorizationCodeServices;

    @Autowired
    @Qualifier("hybridTokenGranterForAuthCodeGrant")
    HybridTokenGranterForAuthorizationCode hybridTokenGranterForAuthCode;

    @Autowired
    @Qualifier("authorizationRequestManager")
    OAuth2RequestFactory oAuth2RequestFactory;

    @Autowired
    @Qualifier("jdbcClientDetailsService")
    MultitenantClientServices clientDetailsService;

    @Autowired
    @Qualifier("oauth2TokenGranter")
    TokenGranter tokenGranter;

    @Autowired
    @Qualifier("pkceValidationServices")
    PkceValidationService pkceValidationService;

    @Autowired
    @Qualifier("uaaAuthorizationEndpoint")
    UaaAuthorizationEndpoint uaaAuthorizationEndpoint;

    ClientParametersAuthenticationFilter clientParameterAuthenticationFilter;
    private synchronized ClientParametersAuthenticationFilter getClientParameterAuthenticationFilter() {
        if (this.clientParameterAuthenticationFilter == null) {
            clientParameterAuthenticationFilter = new ClientParametersAuthenticationFilter();
            clientParameterAuthenticationFilter.setAuthenticationEntryPoint(basicAuthenticationEntryPoint);
            clientParameterAuthenticationFilter.setClientAuthenticationManager(clientAuthenticationManager);
        }
        return this.clientParameterAuthenticationFilter;
    }

    @Bean
    @Order(FilterChainOrder.OAUTH_01)
    UaaFilterChain tokenRevocationFilter(HttpSecurity http, @Qualifier("self") IsSelfCheck selfCheck) throws Exception {
        SecurityFilterChain chain = http
                .securityMatcher("/oauth/token/revoke/**")
                .authorizeHttpRequests( auth -> {
                    auth.requestMatchers("/oauth/token/revoke/client/**").access(anyOf(true).hasScope("tokens.revoke").isUaaAdmin().isZoneAdmin());
                    auth.requestMatchers("/oauth/token/revoke/user/*/client/**").access(anyOf(true).hasScope("tokens.revoke").isUaaAdmin().isZoneAdmin()
                            .or(SelfCheckAuthorizationManager.isUserTokenRevocationForSelf(selfCheck, 4))
                            .or(SelfCheckAuthorizationManager.isClientTokenRevocationForSelf(selfCheck, 6))
                    );
                    auth.requestMatchers("/oauth/token/revoke/user/**").access(anyOf(true)
                            .hasScope("tokens.revoke").isUaaAdmin()
                            .or(SelfCheckAuthorizationManager.isUserTokenRevocationForSelf(selfCheck, 4))
                    );
                    auth.requestMatchers(HttpMethod.DELETE, "/oauth/token/revoke/**").access(anyOf(true)
                            .hasScope("tokens.revoke")
                            .or(SelfCheckAuthorizationManager.isTokenRevocationForSelf(selfCheck, 3))
                    );

                    auth.anyRequest().denyAll();
                })
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(resourceAgnosticAuthenticationFilter.getFilter(), BasicAuthenticationFilter.class)
                .anonymous(AnonymousConfigurer::disable)
                .csrf(CsrfConfigurer::disable)
                .exceptionHandling(exception ->
                        exception.authenticationEntryPoint(oauthAuthenticationEntryPoint)
                                .accessDeniedHandler(oauthAccessDeniedHandler)
                )
                .securityContext(sc -> sc.requireExplicitSave(false))
                .build();

        return new UaaFilterChain(chain, "tokenRevocationFilter");
    }

    @Bean
    @Order(FilterChainOrder.OAUTH_02)
    UaaFilterChain tokenListFilter(HttpSecurity http) throws Exception {
        SecurityFilterChain chain = http
                .securityMatcher("/oauth/token/list/**")
                .authorizeHttpRequests( auth -> {
                    auth.requestMatchers(HttpMethod.GET, "/oauth/token/list/user/**").access(anyOf(true).hasScope("tokens.list").hasScope("uaa.admin"));
                    auth.requestMatchers(HttpMethod.GET, "/oauth/token/list/client/**").access(anyOf(true).hasScope("tokens.list").hasScope("uaa.admin"));
                    auth.anyRequest().denyAll();
                })
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterAt(resourceAgnosticAuthenticationFilter.getFilter(), BasicAuthenticationFilter.class)
                .anonymous(AnonymousConfigurer::disable)
                .csrf(CsrfConfigurer::disable)
                .exceptionHandling(exception ->
                        exception.authenticationEntryPoint(oauthAuthenticationEntryPoint)
                                .accessDeniedHandler(oauthAccessDeniedHandler)
                )
                .securityContext(sc -> sc.requireExplicitSave(false))
                .build();

        return new UaaFilterChain(chain, "tokenListFilter");
    }

    @Bean
    @Order(FilterChainOrder.OAUTH_03)
    UaaFilterChain tokenEndpointSecurityForPasscodes(HttpSecurity http) throws Exception {
        SecurityFilterChain chain = http
                .securityMatcher(passcodeTokenMatcher)
                .authorizeHttpRequests( auth -> {
                    auth.requestMatchers(passcodeTokenMatcher).fullyAuthenticated();
                    auth.requestMatchers("/**").fullyAuthenticated();
                    auth.anyRequest().denyAll();
                })
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                //order should be
                //<custom-filter ref="clientParameterAuthenticationFilter" before="BASIC_AUTH_FILTER"/>
                //<custom-filter ref="clientAuthenticationFilter" position="BASIC_AUTH_FILTER"/>
                //<custom-filter ref="passcodeAuthenticationFilter" after="BASIC_AUTH_FILTER"/>
                .addFilterBefore(getClientParameterAuthenticationFilter(), BasicAuthenticationFilter.class)
                .addFilterAt(clientAuthenticationFilter.getFilter(), BasicAuthenticationFilter.class)
                .addFilterAfter(passcodeAuthenticationFilter.getFilter(), BasicAuthenticationFilter.class)
                .anonymous(AnonymousConfigurer::disable)
                .csrf(CsrfConfigurer::disable)
                .exceptionHandling(exception ->
                        exception.authenticationEntryPoint(basicAuthenticationEntryPoint)
                                .accessDeniedHandler(oauthAccessDeniedHandler)
                )
                .securityContext(sc -> sc.requireExplicitSave(false))
                .build();

        return new UaaFilterChain(chain, "tokenEndpointSecurityForPasscodes");
    }

    @Bean
    @Order(FilterChainOrder.OAUTH_04)
    UaaFilterChain statelessTokenApiSecurity(HttpSecurity http) throws Exception {
        SecurityFilterChain chain = http
                .securityMatcher(oauthTokenApiRequestMatcher)
                .authorizeHttpRequests( auth -> {
                    auth.requestMatchers("/**").access(anyOf(true).hasScope("uaa.user"));
                    auth.anyRequest().denyAll();
                })
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterAt(resourceAgnosticAuthenticationFilter.getFilter(), BasicAuthenticationFilter.class)
                .anonymous(AnonymousConfigurer::disable)
                .csrf(CsrfConfigurer::disable)
                .exceptionHandling(exception ->
                        exception.authenticationEntryPoint(oauthAuthenticationEntryPoint)
                                .accessDeniedHandler(oauthAccessDeniedHandler)
                )
                .securityContext(sc -> sc.requireExplicitSave(false))
                .build();

        return new UaaFilterChain(chain, "statelessTokenApiSecurity");
    }

    @Bean
    @Order(FilterChainOrder.OAUTH_05)
    UaaFilterChain tokenEndpointSecurity(HttpSecurity http) throws Exception {
        SecurityFilterChain chain = http
                .securityMatcher("/oauth/token/**")
                .authenticationManager(clientAuthenticationManager)
                .authorizeHttpRequests( auth -> {
                    auth.requestMatchers("/**").access(anyOf().fullyAuthenticated());
                    auth.anyRequest().denyAll();
                })
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(getClientParameterAuthenticationFilter(), BasicAuthenticationFilter.class)
                .addFilterAt(clientAuthenticationFilter.getFilter(), BasicAuthenticationFilter.class)
                .addFilterAfter(tokenEndpointAuthenticationFilter.getFilter(), BasicAuthenticationFilter.class)
                .anonymous(AnonymousConfigurer::disable)
                .csrf(CsrfConfigurer::disable)
                .exceptionHandling(exception ->
                        exception.authenticationEntryPoint(basicAuthenticationEntryPoint)
                                .accessDeniedHandler(oauthAccessDeniedHandler)
                )
                .securityContext(sc -> sc.requireExplicitSave(false))
                .build();

        return new UaaFilterChain(chain, "tokenEndpointSecurity");
    }

    @Bean
    @Order(FilterChainOrder.OAUTH_06)
    UaaFilterChain statelessAuthzEndpointSecurity(HttpSecurity http) throws Exception {
        SecurityFilterChain chain = http
                .securityMatcher(oauthAuthorizeRequestMatcher)
                .authenticationManager(zoneAwareAuthzAuthenticationManager)
                .authorizeHttpRequests( auth -> {
                    auth.requestMatchers(oauthAuthorizeRequestMatcher).access(anyOf().fullyAuthenticated());
                    auth.anyRequest().denyAll();
                })
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterAt(authzAuthenticationFilter.getFilter(), BasicAuthenticationFilter.class)
                .anonymous(AnonymousConfigurer::disable)
                .csrf(CsrfConfigurer::disable)
                .exceptionHandling(exception ->
                        exception.authenticationEntryPoint(oauthAuthenticationEntryPoint)
                                .accessDeniedHandler(oauthAccessDeniedHandler)
                )
                .securityContext(sc -> sc.requireExplicitSave(false))
                .build();

        return new UaaFilterChain(chain, "statelessAuthzEndpointSecurity");
    }

    @Bean
    @Order(FilterChainOrder.OAUTH_07)
    UaaFilterChain statelessAuthorizeApiSecurity(HttpSecurity http) throws Exception {
        SecurityFilterChain chain = http
                .securityMatcher(oauthAuthorizeApiRequestMatcher)
                .authorizeHttpRequests( auth -> {
                    auth.requestMatchers(oauthAuthorizeApiRequestMatcher).access(anyOf(true).hasScope("uaa.user").isUaaAdmin().isZoneAdmin());
                    auth.anyRequest().denyAll();
                })
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterAt(resourceAgnosticAuthenticationFilter.getFilter(), BasicAuthenticationFilter.class)
                .anonymous(AnonymousConfigurer::disable)
                .csrf(CsrfConfigurer::disable)
                .exceptionHandling(exception ->
                        exception.authenticationEntryPoint(oauthAuthenticationEntryPoint)
                                .accessDeniedHandler(oauthAccessDeniedHandler)
                )
                .securityContext(sc -> sc.requireExplicitSave(false))
                .build();

        return new UaaFilterChain(chain, "statelessAuthorizeApiSecurity");
    }

    @Bean
    @Order(FilterChainOrder.OAUTH_08)
    UaaFilterChain promptStatelessTokenApiSecurity(HttpSecurity http) throws Exception {
        SecurityFilterChain chain = http
                .securityMatcher(promptOauthAuthorizeApiRequestMatcher)
                .authorizeHttpRequests( auth -> {
                    auth.requestMatchers(promptOauthAuthorizeApiRequestMatcher).fullyAuthenticated();
                    auth.anyRequest().denyAll();
                })
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.NEVER))
                .addFilterAfter(passwordChangeRequiredFilter.getFilter(), BasicAuthenticationFilter.class)
                .addFilterBefore(currentUserCookieFilter.getFilter(), FilterSecurityInterceptor.class)
                .anonymous(AnonymousConfigurer::disable)
                .csrf(CsrfConfigurer::disable)
                .exceptionHandling(exception ->
                        exception.authenticationEntryPoint(uaaAuthorizationEndpoint)
                                .accessDeniedHandler(oauthAccessDeniedHandler)
                )
                .securityContext(sc -> sc.requireExplicitSave(false))
                .build();

        return new UaaFilterChain(chain, "promptStatelessTokenApiSecurity");
    }

    @Bean
    @Order(FilterChainOrder.OAUTH_09)
    UaaFilterChain externalOAuthCallbackEndpointSecurity(HttpSecurity http) throws Exception {
        SecurityFilterChain chain = http
                .securityMatcher(externalOAuthCallbackRequestMatcher)
                .authenticationManager(zoneAwareAuthzAuthenticationManager)
                .authorizeHttpRequests( auth -> {
                    auth.requestMatchers(externalOAuthCallbackRequestMatcher).access(anyOf().fullyAuthenticated());
                    auth.anyRequest().denyAll();
                })
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.NEVER))
                .addFilterAt(externalOAuthCallbackAuthenticationFilter.getFilter(), BasicAuthenticationFilter.class)
                .anonymous(AnonymousConfigurer::disable)
                .csrf(CsrfConfigurer::disable)
                .exceptionHandling(exception ->
                        exception.authenticationEntryPoint(loginEntryPoint)
                )
                .securityContext(sc -> sc.requireExplicitSave(false))
                .build();

        return new UaaFilterChain(chain, "externalOAuthCallbackEndpointSecurity");
    }

    @Bean
    @Order(FilterChainOrder.OAUTH_10)
    UaaFilterChain oldAuthzEndpointSecurity(HttpSecurity http) throws Exception {
        SecurityFilterChain chain = http
                .securityMatcher(oauthAuthorizeRequestMatcherOld)
                .authenticationManager(zoneAwareAuthzAuthenticationManager)
                .authorizeHttpRequests( auth -> {
                    auth.requestMatchers(oauthAuthorizeRequestMatcherOld).access(anyOf().fullyAuthenticated());
                    auth.anyRequest().denyAll();
                })
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.NEVER))
                .addFilterAt(authzAuthenticationFilter.getFilter(), BasicAuthenticationFilter.class)
                .anonymous(AnonymousConfigurer::disable)
                .csrf(CsrfConfigurer::disable)
                .exceptionHandling(exception ->
                        exception.authenticationEntryPoint(oauthAuthenticationEntryPoint)
                                .accessDeniedHandler(oauthAccessDeniedHandler)
                )
                .securityContext(sc -> sc.requireExplicitSave(false))
                .build();

        return new UaaFilterChain(chain, "oldAuthzEndpointSecurity");
    }
}
