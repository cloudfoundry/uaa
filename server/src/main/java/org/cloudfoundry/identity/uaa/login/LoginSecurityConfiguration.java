package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.authentication.PasswordChangeUiRequiredFilter;
import org.cloudfoundry.identity.uaa.authentication.ReAuthenticationRequiredFilter;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetailsSource;
import org.cloudfoundry.identity.uaa.security.CsrfAwareEntryPointAndDeniedHandler;
import org.cloudfoundry.identity.uaa.security.web.CookieBasedCsrfTokenRepository;
import org.cloudfoundry.identity.uaa.security.web.HttpsHeaderFilter;
import org.cloudfoundry.identity.uaa.web.FilterChainOrder;
import org.cloudfoundry.identity.uaa.web.UaaFilterChain;
import org.cloudfoundry.identity.uaa.web.UaaSavedRequestCache;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.support.ResourcePropertySource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.session.DisableEncodeUrlFilter;

import java.io.IOException;

import static org.cloudfoundry.identity.uaa.web.AuthorizationManagersUtils.anonymousOrFullyAuthenticated;

@Configuration
@EnableWebSecurity
class LoginSecurityConfiguration {

    @Bean
    ResourcePropertySource messagePropertiesSource() throws IOException {
        return new ResourcePropertySource("messages.properties");
    }

    @Bean
    @Order(FilterChainOrder.VERIFY_USER)
    UaaFilterChain verifyUser(HttpSecurity http) throws Exception {
        var originalChain = http
                .securityMatcher("/verify_user")
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                .csrf(CsrfConfigurer::disable)
                .exceptionHandling(exception -> {
                    exception.authenticationEntryPoint(new CsrfAwareEntryPointAndDeniedHandler("/invalid_request", "/login?error=invalid_login_request"));
                })
                .build();
        return new UaaFilterChain(originalChain);
    }

    @Bean
    @Order(FilterChainOrder.INVITATIONS_ACCEPT)
    UaaFilterChain acceptInvitation(HttpSecurity http) throws Exception {
        var originalChain = http
                .securityMatcher("/invitations/accept")
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                .csrf(CsrfConfigurer::disable)
                .exceptionHandling(exception -> {
                    exception.authenticationEntryPoint(new CsrfAwareEntryPointAndDeniedHandler("/invalid_request", "/login?error=invalid_login_request"));
                })
                .build();
        return new UaaFilterChain(originalChain);
    }

    /**
     * Handle login callbacks from SAML upstream providers.
     */
    @Bean
    @Order(FilterChainOrder.SAML_IDP_SSO)
    UaaFilterChain samlSsoCallback(
            HttpSecurity http,
            PasswordChangeUiRequiredFilter passwordChangeUiRequiredFilter
    ) throws Exception {
        var originalChain = http
                .securityMatcher("/saml/idp/SSO/**")
                .authorizeHttpRequests(auth -> auth.anyRequest().fullyAuthenticated())
                .addFilterBefore(passwordChangeUiRequiredFilter, BasicAuthenticationFilter.class)
                .csrf(CsrfConfigurer::disable)
                .exceptionHandling(exception -> {
                    exception.authenticationEntryPoint(new CsrfAwareEntryPointAndDeniedHandler("/invalid_request", "/login?error=invalid_login_request"));
                })
                .build();
        return new UaaFilterChain(originalChain);
    }

    /**
     * Handle the UI-related components, such as the login page, the home page, etc.
     * <p>
     * This is the catch-all "any-request" filter-chain that is executed last.
     * <p>
     * TODO: remove the dependence on the "uiSecurity" name (e.g. in SecurityFilterChainPostProcessor)
     */
    @Bean
    @Order(FilterChainOrder.UI_SECURITY)
    UaaFilterChain uiSecurity(
            HttpSecurity http,
            @Qualifier("zoneAwareAuthzAuthenticationManager") AuthenticationManager authenticationManager,
            ReAuthenticationRequiredFilter reAuthenticationRequiredFilter,
            PasswordChangeUiRequiredFilter passwordChangeUiRequiredFilter,
            LogoutFilter logoutFilter,
            CookieBasedCsrfTokenRepository csrfTokenRepository,
            UaaSavedRequestCache clientRedirectStateCache, // TODO: remove bean
            AccountSavingAuthenticationSuccessHandler loginSuccessHandler,
            UaaAuthenticationFailureHandler loginFailureHandler
    ) throws Exception {

        var originalChain = http
                .csrf(csrf -> csrf.csrfTokenRepository(csrfTokenRepository))
                .authenticationManager(authenticationManager)
                .authorizeHttpRequests(auth -> {
                    auth.requestMatchers("/force_password_change/**").fullyAuthenticated();
                    auth.requestMatchers("/reset_password**").anonymous();
                    auth.requestMatchers("/create_account*").anonymous();
                    auth.requestMatchers("/login/idp_discovery/**").anonymous();
                    auth.requestMatchers("/saml/metadata/**").anonymous();
                    auth.requestMatchers("/origin-chooser").anonymous();
                    auth.requestMatchers("/login**").access(anonymousOrFullyAuthenticated());
                    auth.requestMatchers("/**").fullyAuthenticated();
                })
                .formLogin(login -> {
                    login.loginPage("/login");
                    login.usernameParameter("username");
                    login.passwordParameter("password");
                    login.loginProcessingUrl("/login.do");
                    login.defaultSuccessUrl("/"); // TODO is this exactly the same?
                    login.successHandler(loginSuccessHandler);
                    login.failureHandler(loginFailureHandler);
                    login.authenticationDetailsSource(new UaaAuthenticationDetailsSource());
                })
                .addFilterBefore(new HttpsHeaderFilter(), DisableEncodeUrlFilter.class)
                // TODO: Opt in to SecurityContextHolder filter instead of SecurityContextPersistenceFilter
                // See: https://docs.spring.io/spring-security/reference/5.8/migration/servlet/session-management.html
                .addFilterAfter(reAuthenticationRequiredFilter, SecurityContextPersistenceFilter.class)
                .addFilterBefore(clientRedirectStateCache, CsrfFilter.class)
                .addFilterBefore(passwordChangeUiRequiredFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(logoutFilter, LogoutFilter.class)
                .exceptionHandling(exception -> {
                    // TODO: make common?
                    exception.accessDeniedHandler(new CsrfAwareEntryPointAndDeniedHandler("/invalid_request", "/login?error=invalid_login_request"));
                })
                .requestCache(cache -> cache.requestCache(clientRedirectStateCache))
                .build();
        return new UaaFilterChain(originalChain);
    }

}
