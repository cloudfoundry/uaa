package org.cloudfoundry.identity.uaa.client;

import org.cloudfoundry.identity.uaa.oauth.UaaTokenServices;
import org.cloudfoundry.identity.uaa.oauth.provider.authentication.OAuth2AuthenticationManager;
import org.cloudfoundry.identity.uaa.oauth.provider.authentication.OAuth2AuthenticationProcessingFilter;
import org.cloudfoundry.identity.uaa.oauth.provider.error.OAuth2AccessDeniedHandler;
import org.cloudfoundry.identity.uaa.oauth.provider.error.OAuth2AuthenticationEntryPoint;
import org.cloudfoundry.identity.uaa.web.FilterChainOrder;
import org.cloudfoundry.identity.uaa.web.UaaFilterChain;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

import static org.cloudfoundry.identity.uaa.web.AuthorizationManagersUtils.anyOf;

@Configuration
@EnableWebSecurity
class ClientAdminSecurityConfiguration {

    @Bean
    @Order(FilterChainOrder.CLIENT_ADMIN)
    UaaFilterChain clientAdminSecret(
            HttpSecurity http,
            @Qualifier("oauthAuthenticationEntryPoint") OAuth2AuthenticationEntryPoint oauthAuthenticationEntryPoint,
            @Qualifier("oauthAccessDeniedHandler") OAuth2AccessDeniedHandler oauthAccessDeniedHandler,
            @Qualifier("clientAdminOAuth2ResourceFilter") FilterRegistrationBean<OAuth2AuthenticationProcessingFilter> resourceFilter
    ) throws Exception {
        var originalChain = http
                .securityMatcher("/oauth/clients/**")
                .authorizeHttpRequests(auth -> {

                    auth.requestMatchers("/oauth/clients/*/secret").access(isAdminOrHasScopes("clients.secret"));

                    auth.requestMatchers("/oauth/clients/*/clientjwt").access(isAdminOrHasScopes("clients.trust"));

                    auth.requestMatchers(HttpMethod.POST, "/oauth/clients/tx/**").access(isAdminOrHasScopes());
                    auth.requestMatchers(HttpMethod.PUT, "/oauth/clients/tx/**").access(isAdminOrHasScopes());
                    auth.requestMatchers(HttpMethod.DELETE, "/oauth/clients/tx/**").access(isAdminOrHasScopes());

                    auth.requestMatchers(HttpMethod.GET, "oauth/clients/meta", "/oauth/clients/*/meta").fullyAuthenticated();

                    auth.requestMatchers(HttpMethod.GET, "/oauth/clients/**").access(isAdminOrHasScopes("clients.read"));

                    auth.requestMatchers(HttpMethod.POST, "/oauth/clients/**").access(isAdminOrHasScopes("clients.write"));
                    auth.requestMatchers(HttpMethod.PUT, "/oauth/clients/**").access(isAdminOrHasScopes("clients.write"));
                    auth.requestMatchers(HttpMethod.DELETE, "/oauth/clients/**").access(isAdminOrHasScopes("clients.write"));

                    auth.anyRequest().denyAll();
                })
                .addFilterAt(resourceFilter.getFilter(), AbstractPreAuthenticatedProcessingFilter.class)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .csrf(CsrfConfigurer::disable)
                .exceptionHandling(exception -> {
                    exception.authenticationEntryPoint(oauthAuthenticationEntryPoint);
                    exception.accessDeniedHandler(oauthAccessDeniedHandler);
                })
                .securityContext(sc -> sc.requireExplicitSave(false))
                .build();
        return new UaaFilterChain(originalChain, "clientAdminCatchAll");
    }

    // TODO: object provider?
    @Bean(name = "clientAdminOAuth2ResourceFilter")
    public FilterRegistrationBean<OAuth2AuthenticationProcessingFilter> clientAdminOAuth2ResourceFilter(
            UaaTokenServices tokenServices,
            @Qualifier("oauthAuthenticationEntryPoint") OAuth2AuthenticationEntryPoint oauthAuthenticationEntryPoint
    ) {
        var oauth2AuthenticationManager = new OAuth2AuthenticationManager();
        oauth2AuthenticationManager.setTokenServices(tokenServices);
        var oauth2ResourceFilter = new OAuth2AuthenticationProcessingFilter();
        oauth2ResourceFilter.setAuthenticationManager(oauth2AuthenticationManager);
        oauth2ResourceFilter.setAuthenticationEntryPoint(oauthAuthenticationEntryPoint);
        FilterRegistrationBean<OAuth2AuthenticationProcessingFilter> bean = new FilterRegistrationBean<>(oauth2ResourceFilter);
        bean.setEnabled(false);
        return bean;
    }

    /**
     * The user either:
     * <ul>
     * <li>is UAA admin</li>
     * <li>is Zone admin</li>
     * <li>has scope clients.admin</li>
     * <li>has any of the scopes in {@code scopes}</li>
     * </ul>
     */
    public static AuthorizationManager<RequestAuthorizationContext> isAdminOrHasScopes(String... scopes) {
        String[] requiredScopes = new String[scopes.length + 1];
        requiredScopes[0] = "clients.admin";
        System.arraycopy(scopes, 0, requiredScopes, 1, scopes.length);
        return anyOf()
                .isUaaAdmin()
                .isZoneAdmin()
                .hasScope(requiredScopes)
                .throwOnMissingScope();
    }

}
