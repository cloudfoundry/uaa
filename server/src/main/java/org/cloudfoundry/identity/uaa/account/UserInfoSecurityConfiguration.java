package org.cloudfoundry.identity.uaa.account;

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
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

import static org.cloudfoundry.identity.uaa.web.AuthorizationManagersUtils.anyOf;

@Configuration
@EnableWebSecurity
class UserInfoSecurityConfiguration {

    @Bean
    @Order(FilterChainOrder.USERINFO)
    UaaFilterChain userinfo(
            HttpSecurity http,
            UaaTokenServices tokenServices,
            @Qualifier("oauthAccessDeniedHandler") OAuth2AccessDeniedHandler oauthAccessDeniedHandler,
            @Qualifier("oauthAuthenticationEntryPoint") OAuth2AuthenticationEntryPoint oauthAuthenticationEntryPoint
    ) throws Exception {
        var oauth2AuthenticationManager = new OAuth2AuthenticationManager();
        oauth2AuthenticationManager.setTokenServices(tokenServices);
        oauth2AuthenticationManager.setResourceId("openid");
        var oidcResourceAuthenticationFilter = new OAuth2AuthenticationProcessingFilter();
        oidcResourceAuthenticationFilter.setAuthenticationManager(oauth2AuthenticationManager);
        oidcResourceAuthenticationFilter.setAuthenticationEntryPoint(oauthAuthenticationEntryPoint);

        var originalChain = http
                .securityMatcher("/userinfo")
                .authorizeHttpRequests(auth -> auth.anyRequest().access(anyOf().hasScope("openid")))
                .addFilterBefore(oidcResourceAuthenticationFilter, AbstractPreAuthenticatedProcessingFilter.class)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                // Although it is RECOMMENDED that /userinfo requests be GET requests, they MAY be POST requests.
                // We disable CSRF protection for that use-case.
                // https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
                .csrf(CsrfConfigurer::disable)
                .exceptionHandling(exception -> {
                    exception.authenticationEntryPoint(oauthAuthenticationEntryPoint);
                    exception.accessDeniedHandler(oauthAccessDeniedHandler);
                })
                .securityContext(sc -> sc.requireExplicitSave(false))
                .build();
        return new UaaFilterChain(originalChain, "userinfo");
    }

}
