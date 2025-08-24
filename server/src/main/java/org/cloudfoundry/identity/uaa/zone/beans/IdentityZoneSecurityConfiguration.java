package org.cloudfoundry.identity.uaa.zone.beans;

import org.cloudfoundry.identity.uaa.oauth.UaaTokenServices;
import org.cloudfoundry.identity.uaa.oauth.provider.authentication.OAuth2AuthenticationManager;
import org.cloudfoundry.identity.uaa.oauth.provider.authentication.OAuth2AuthenticationProcessingFilter;
import org.cloudfoundry.identity.uaa.oauth.provider.error.OAuth2AccessDeniedHandler;
import org.cloudfoundry.identity.uaa.oauth.provider.error.OAuth2AuthenticationEntryPoint;
import org.cloudfoundry.identity.uaa.web.FilterChainOrder;
import org.cloudfoundry.identity.uaa.web.UaaFilterChain;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.authentication.AuthenticationManagerBeanDefinitionParser;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import static org.cloudfoundry.identity.uaa.web.AuthorizationManagersUtils.anyOf;

@Configuration
@EnableWebSecurity
class IdentityZoneSecurityConfiguration {

    @Bean
    @Order(FilterChainOrder.IDENTITY_ZONES)
    public SecurityFilterChain identityZones(
            HttpSecurity http,
            UaaTokenServices tokenServices,
            @Qualifier("oauthAccessDeniedHandler") OAuth2AccessDeniedHandler oauthAccessDeniedHandler,
            @Qualifier("oauthAuthenticationEntryPoint") OAuth2AuthenticationEntryPoint oauthAuthenticationEntryPoint
    ) throws Exception {
        var emptyAuthenticationManager = new ProviderManager(new AuthenticationManagerBeanDefinitionParser.NullAuthenticationProvider());

        OAuth2AuthenticationManager authenticationManager = new OAuth2AuthenticationManager();
        authenticationManager.setTokenServices(tokenServices);
        OAuth2AuthenticationProcessingFilter oauth2ResourceFilter = new OAuth2AuthenticationProcessingFilter();
        oauth2ResourceFilter.setAuthenticationManager(authenticationManager);
        oauth2ResourceFilter.setAuthenticationEntryPoint(oauthAuthenticationEntryPoint);

        var originalFilterChain = http
                .securityMatcher("/identity-zones/**", "/identity-providers/**")
                .authenticationManager(emptyAuthenticationManager)
                .authorizeHttpRequests(auth -> {
                    auth.requestMatchers(HttpMethod.GET, "/identity-zones").access(
                            anyOf()
                                    .isUaaAdmin()
                                    .isZoneAdmin()
                                    .hasScopeWithZoneId("zones.read")
                                    .hasScope("zones.write")
                                    .throwOnMissingScope()
                    );
                    auth.requestMatchers(HttpMethod.POST, "/identity-zones/*/clients").access(
                            anyOf()
                                    .isUaaAdmin()
                                    .hasScopeWithZoneId("zones.write")
                                    .throwOnMissingScope()
                    );
                    auth.requestMatchers(HttpMethod.DELETE, "/identity-zones/*/clients/*").access(
                            anyOf()
                                    .isUaaAdmin()
                                    .hasScopeWithZoneId("zones.write")
                                    .throwOnMissingScope()
                    );

                    auth.requestMatchers(HttpMethod.GET, "/identity-zones/*").access(
                            anyOf()
                                    .isUaaAdmin()
                                    .isZoneAdmin()
                                    .hasScopeWithZoneId("zones.read")
                                    .hasScopeWithZoneId("zones.{zone.id}.read")
                                    .hasScope("zones.write")
                                    .throwOnMissingScope()
                    );

                    auth.requestMatchers(HttpMethod.POST, "/identity-zones/**").access(
                            anyOf()
                                    .isUaaAdmin()
                                    .isZoneAdmin()
                                    .hasScopeWithZoneId("zones.write")
                                    .throwOnMissingScope()
                    );
                    auth.requestMatchers(HttpMethod.DELETE, "/identity-zones/**").access(
                            anyOf()
                                    .isUaaAdmin()
                                    .isZoneAdmin()
                                    .hasScopeWithZoneId("zones.write")
                                    .throwOnMissingScope()
                    );

                    auth.requestMatchers(HttpMethod.PUT, "/identity-zones/**").access(
                            anyOf()
                                    .isUaaAdmin()
                                    .isZoneAdmin()
                                    .hasScopeWithZoneId("zones.write")
                                    .hasScope("zones.write")
                                    .throwOnMissingScope()
                    );

                    auth.requestMatchers(HttpMethod.GET, "/identity-providers/**").access(
                            anyOf()
                                    .isUaaAdmin()
                                    .isZoneAdmin()
                                    .hasScope("idps.read")
                                    .throwOnMissingScope()
                    );

                    var canWriteIdp = anyOf()
                            .isUaaAdmin()
                            .isZoneAdmin()
                            .hasScope("idps.write")
                            .throwOnMissingScope();
                    auth.requestMatchers(HttpMethod.POST, "/identity-providers/**").access(canWriteIdp);
                    auth.requestMatchers(HttpMethod.PUT, "/identity-providers/**").access(canWriteIdp);
                    auth.requestMatchers(HttpMethod.PATCH, "/identity-providers/**").access(canWriteIdp);
                    auth.requestMatchers(HttpMethod.DELETE, "/identity-providers/**").access(canWriteIdp);

                    auth.requestMatchers("/identity-providers/**").denyAll();
                    auth.requestMatchers("/identity-zones/**").denyAll();
                })
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(oauth2ResourceFilter, AbstractPreAuthenticatedProcessingFilter.class)
                .csrf(CsrfConfigurer::disable)
                .exceptionHandling(exception -> {
                    exception.authenticationEntryPoint(oauthAuthenticationEntryPoint);
                    exception.accessDeniedHandler(oauthAccessDeniedHandler);
                })
                .securityContext(sc -> sc.requireExplicitSave(false))
                .build();
        return new UaaFilterChain(originalFilterChain, "identityZones");
    }

}
