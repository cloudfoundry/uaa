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

import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import org.cloudfoundry.identity.uaa.authentication.ClientBasicAuthenticationFilter;
import org.cloudfoundry.identity.uaa.authentication.ClientDetailsAuthenticationProvider;
import org.cloudfoundry.identity.uaa.authentication.ClientParametersAuthenticationFilter;
import org.cloudfoundry.identity.uaa.authentication.PasscodeAuthenticationFilter;
import org.cloudfoundry.identity.uaa.authentication.manager.AuthzAuthenticationManager;
import org.cloudfoundry.identity.uaa.authentication.manager.CheckIdpEnabledAuthenticationManager;
import org.cloudfoundry.identity.uaa.authentication.manager.CommonLoginPolicy;
import org.cloudfoundry.identity.uaa.authentication.manager.DynamicZoneAwareAuthenticationManager;
import org.cloudfoundry.identity.uaa.authentication.manager.PasswordGrantAuthenticationManager;
import org.cloudfoundry.identity.uaa.authentication.manager.PeriodLockoutPolicy;
import org.cloudfoundry.identity.uaa.authentication.manager.UserLockoutPolicyRetriever;
import org.cloudfoundry.identity.uaa.client.UaaClientDetailsUserDetailsService;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetailsService;
import org.cloudfoundry.identity.uaa.oauth.provider.authentication.OAuth2AuthenticationProcessingFilter;
import org.cloudfoundry.identity.uaa.oauth.provider.error.OAuth2AccessDeniedHandler;
import org.cloudfoundry.identity.uaa.oauth.provider.error.OAuth2AuthenticationEntryPoint;
import org.cloudfoundry.identity.uaa.provider.LockoutPolicy;
import org.cloudfoundry.identity.uaa.security.CsrfAwareEntryPointAndDeniedHandler;
import org.cloudfoundry.identity.uaa.security.IsSelfCheck;
import org.cloudfoundry.identity.uaa.security.web.UaaRequestMatcher;
import org.cloudfoundry.identity.uaa.user.JdbcUaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.util.CachingPasswordEncoder;
import org.cloudfoundry.identity.uaa.web.BackwardsCompatibleScopeParsingFilter;
import org.cloudfoundry.identity.uaa.web.FilterChainOrder;
import org.cloudfoundry.identity.uaa.web.SelfCheckAuthorizationManager;
import org.cloudfoundry.identity.uaa.web.UaaFilterChain;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.config.SetFactoryBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AnonymousConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import static java.util.Arrays.asList;
import static java.util.Map.entry;
import static org.cloudfoundry.identity.uaa.web.AuthorizationManagersUtils.anyOf;

@Configuration
@EnableWebSecurity
class OauthEndpointSecurityConfiguration {

    @Autowired
    @Qualifier("oauthAuthenticationEntryPoint")
    OAuth2AuthenticationEntryPoint oauthAuthenticationEntryPoint;

    @Autowired
    @Qualifier("oauthAccessDeniedHandler")
    OAuth2AccessDeniedHandler oauthAccessDeniedHandler;

    @Autowired
    @Qualifier("resourceAgnosticAuthenticationFilter")
    OAuth2AuthenticationProcessingFilter resourceAgnosticAuthenticationFilter;

    @Autowired
    @Qualifier("jdbcClientDetailsService")
    ClientDetailsService jdbcClientDetailsService;

    @Autowired
    @Qualifier("userDatabase")
    UaaUserDatabase userDatabase;

    @Bean("loginEntryPoint")
    CsrfAwareEntryPointAndDeniedHandler loginEntryPoint() {
        return new CsrfAwareEntryPointAndDeniedHandler("/invalid_request", "/login?error=invalid_login_request");
    }

    @Autowired
    @Qualifier("cachingPasswordEncoder")
    CachingPasswordEncoder cachingPasswordEncoder;

    @Autowired
    @Qualifier("passcodeTokenMatcher")
    UaaRequestMatcher passcodeTokenMatcher;

    @Autowired
    @Qualifier("backwardsCompatibleScopeParameter")
    BackwardsCompatibleScopeParsingFilter backwardsCompatibleScopeParameter;

    @Autowired
    @Qualifier("clientParameterAuthenticationFilter")
    ClientParametersAuthenticationFilter clientParameterAuthenticationFilter;

    @Autowired
    @Qualifier("clientAuthenticationFilter")
    ClientBasicAuthenticationFilter clientAuthenticationFilter;

    @Autowired
    @Qualifier("passcodeAuthenticationFilter")
    PasscodeAuthenticationFilter passcodeAuthenticationFilter;

    @Bean
    @Order(FilterChainOrder.OAUTH)
    UaaFilterChain tokenRevocationFilter(HttpSecurity http, @Qualifier("self") IsSelfCheck selfCheck) throws Exception {
        SecurityFilterChain chain = http
                .securityMatcher("/oauth/token/revoke/**")
                .authorizeHttpRequests( auth -> {
                    auth.requestMatchers("/oauth/token/revoke/client/**").access(anyOf(true).hasScope("tokens.revoke"));
                    auth.requestMatchers("/oauth/token/revoke/user/**/client/**").access(anyOf(true)
                            .hasScope("tokens.revoke").isUaaAdmin()
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
                .addFilterBefore(resourceAgnosticAuthenticationFilter, BasicAuthenticationFilter.class)
                .anonymous(AnonymousConfigurer::disable)
                .csrf(CsrfConfigurer::disable)
                .exceptionHandling(exception ->
                        exception.authenticationEntryPoint(oauthAuthenticationEntryPoint)
                                .accessDeniedHandler(oauthAccessDeniedHandler)
                )
                .build();

        return new UaaFilterChain(chain, "tokenRevocationFilter");
    }

    @Bean
    @Order(FilterChainOrder.OAUTH)
    UaaFilterChain tokenListFilter(HttpSecurity http) throws Exception {
        SecurityFilterChain chain = http
                .securityMatcher("/oauth/token/list/**")
                .authorizeHttpRequests( auth -> {
                    auth.requestMatchers(HttpMethod.GET, "/oauth/token/list/user/**").access(anyOf(true).hasScope("tokens.list"));
                    auth.requestMatchers(HttpMethod.GET, "/oauth/token/list/client/**").access(anyOf(true).hasScope("tokens.list"));
                    auth.anyRequest().denyAll();
                })
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(resourceAgnosticAuthenticationFilter, BasicAuthenticationFilter.class)
                .anonymous(AnonymousConfigurer::disable)
                .csrf(CsrfConfigurer::disable)
                .exceptionHandling(exception ->
                        exception.authenticationEntryPoint(oauthAuthenticationEntryPoint)
                                .accessDeniedHandler(oauthAccessDeniedHandler)
                )
                .build();

        return new UaaFilterChain(chain, "tokenListFilter");
    }

    @Bean
    @Order(FilterChainOrder.OAUTH)
    UaaFilterChain tokenEndpointSecurityForPasscodes(HttpSecurity http) throws Exception {
        SecurityFilterChain chain = http
                .securityMatcher(passcodeTokenMatcher)
                .authorizeHttpRequests( auth -> {
                    auth.requestMatchers("/**").access(anyOf().fullyAuthenticated());
                    auth.anyRequest().denyAll();
                })
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                .addFilterAt(clientAuthenticationFilter, BasicAuthenticationFilter.class)
                .addFilterAt(clientAuthenticationFilter, BasicAuthenticationFilter.class)
                .addFilterAt(clientAuthenticationFilter, BasicAuthenticationFilter.class)
                .addFilterAt(clientAuthenticationFilter, BasicAuthenticationFilter.class)
                .addFilterBefore()

                .anonymous(AnonymousConfigurer::disable)
                .csrf(CsrfConfigurer::disable)
                .exceptionHandling(exception ->
                        exception.authenticationEntryPoint(oauthAuthenticationEntryPoint)
                                .accessDeniedHandler(oauthAccessDeniedHandler)
                )
                .build();

        return new UaaFilterChain(chain, "tokenEndpointSecurityForPasscodes");
    }
}
