package org.cloudfoundry.identity.uaa.spiffe;

import org.cloudfoundry.identity.uaa.authentication.ClientBasicAuthenticationFilter;
import org.cloudfoundry.identity.uaa.oauth.provider.error.OAuth2AccessDeniedHandler;
import org.cloudfoundry.identity.uaa.oauth.provider.error.OAuth2AuthenticationEntryPoint;
import org.cloudfoundry.identity.uaa.web.FilterChainOrder;
import org.cloudfoundry.identity.uaa.web.UaaFilterChain;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
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

/** Protects {@code /jwt-svid/**} with client HTTP-Basic auth requiring the uaa.resource authority. */
@Configuration
@EnableWebSecurity
@ConditionalOnProperty(prefix = "uaa.spiffe", name = "instance-identity-ca")
public class SpiffeSecurityConfiguration {

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
    @Qualifier("clientAuthenticationFilter")
    FilterRegistrationBean<ClientBasicAuthenticationFilter> clientAuthenticationFilter;

    @Bean
    @Order(FilterChainOrder.RESOURCE)
    UaaFilterChain jwtSvidSecurity(HttpSecurity http) throws Exception {
        SecurityFilterChain chain = http
                .securityMatcher("/jwt-svid/**")
                .authorizeHttpRequests(auth -> {
                    auth.requestMatchers("/**").hasAuthority("uaa.resource");
                    auth.anyRequest().denyAll();
                })
                .authenticationManager(clientAuthenticationManager)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterAt(clientAuthenticationFilter.getFilter(), BasicAuthenticationFilter.class)
                .anonymous(AnonymousConfigurer::disable)
                .csrf(CsrfConfigurer::disable)
                .exceptionHandling(exception ->
                        exception.authenticationEntryPoint(basicAuthenticationEntryPoint)
                                .accessDeniedHandler(oauthAccessDeniedHandler))
                .securityContext(sc -> sc.requireExplicitSave(false))
                .build();

        return new UaaFilterChain(chain, "jwtSvidSecurity");
    }
}
