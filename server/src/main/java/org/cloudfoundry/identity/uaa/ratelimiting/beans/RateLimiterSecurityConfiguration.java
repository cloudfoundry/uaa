package org.cloudfoundry.identity.uaa.ratelimiting.beans;

import org.cloudfoundry.identity.uaa.authentication.ClientBasicAuthenticationFilter;
import org.cloudfoundry.identity.uaa.oauth.provider.authentication.OAuth2AuthenticationProcessingFilter;
import org.cloudfoundry.identity.uaa.oauth.provider.error.OAuth2AccessDeniedHandler;
import org.cloudfoundry.identity.uaa.oauth.provider.error.OAuth2AuthenticationEntryPoint;
import org.cloudfoundry.identity.uaa.web.FilterChainOrder;
import org.cloudfoundry.identity.uaa.web.UaaFilterChain;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
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
class RateLimiterSecurityConfiguration {


    @Autowired
    @Qualifier("basicAuthenticationEntryPoint")
    OAuth2AuthenticationEntryPoint basicAuthenticationEntryPoint;

    @Autowired
    @Qualifier("clientAuthenticationManager")
    AuthenticationManager clientAuthenticationManager;

    @Autowired
    @Qualifier("oauthAccessDeniedHandler")
    OAuth2AccessDeniedHandler oauthAccessDeniedHandler;

    @Autowired
    @Qualifier("oauthWithoutResourceAuthenticationFilter")
    OAuth2AuthenticationProcessingFilter oauthWithoutResourceAuthenticationFilter;

    @Autowired
    @Qualifier("clientAuthenticationFilter")
    ClientBasicAuthenticationFilter clientAuthenticationFilter;

    @Bean
    @Order(FilterChainOrder.RESOURCE)
    UaaFilterChain ratelimitSecurity(HttpSecurity http) throws Exception {
        SecurityFilterChain chain = http
                .securityMatcher("/RateLimitingStatus/**")
                .authorizeHttpRequests( auth -> {
                    auth.requestMatchers("/**").hasAuthority("uaa.admin");
                    auth.anyRequest().denyAll();
                })
                //TODO is the auth manager needed?
                .authenticationManager(clientAuthenticationManager)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(oauthWithoutResourceAuthenticationFilter, BasicAuthenticationFilter.class)
                .addFilterAt(clientAuthenticationFilter, BasicAuthenticationFilter.class)
                .anonymous(AnonymousConfigurer::disable)
                .csrf(CsrfConfigurer::disable)
                .exceptionHandling(exception ->
                        exception.authenticationEntryPoint(basicAuthenticationEntryPoint)
                                .accessDeniedHandler(oauthAccessDeniedHandler)
                )
                .build();

        return new UaaFilterChain(chain, "ratelimitSecurity");
    }
}
