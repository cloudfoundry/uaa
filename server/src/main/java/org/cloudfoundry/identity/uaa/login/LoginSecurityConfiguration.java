package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.account.ResetPasswordAuthenticationFilter;
import org.cloudfoundry.identity.uaa.authentication.AuthzAuthenticationFilter;
import org.cloudfoundry.identity.uaa.authentication.ClientBasicAuthenticationFilter;
import org.cloudfoundry.identity.uaa.authentication.PasswordChangeUiRequiredFilter;
import org.cloudfoundry.identity.uaa.authentication.ReAuthenticationRequiredFilter;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetailsSource;
import org.cloudfoundry.identity.uaa.invitations.InvitationsAuthenticationTrustResolver;
import org.cloudfoundry.identity.uaa.oauth.provider.authentication.OAuth2AuthenticationProcessingFilter;
import org.cloudfoundry.identity.uaa.oauth.provider.error.OAuth2AccessDeniedHandler;
import org.cloudfoundry.identity.uaa.oauth.provider.error.OAuth2AuthenticationEntryPoint;
import org.cloudfoundry.identity.uaa.provider.saml.UaaDelegatingLogoutSuccessHandler;
import org.cloudfoundry.identity.uaa.scim.DisableUserManagementSecurityFilter;
import org.cloudfoundry.identity.uaa.security.CsrfAwareEntryPointAndDeniedHandler;
import org.cloudfoundry.identity.uaa.security.web.CookieBasedCsrfTokenRepository;
import org.cloudfoundry.identity.uaa.security.web.HttpsHeaderFilter;
import org.cloudfoundry.identity.uaa.security.web.UaaRequestMatcher;
import org.cloudfoundry.identity.uaa.web.FilterChainOrder;
import org.cloudfoundry.identity.uaa.web.UaaFilterChain;
import org.cloudfoundry.identity.uaa.web.UaaSavedRequestCache;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.support.ResourcePropertySource;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AnonymousConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.config.authentication.AuthenticationManagerBeanDefinitionParser;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.CookieClearingLogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfLogoutHandler;
import org.springframework.security.web.session.DisableEncodeUrlFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.cloudfoundry.identity.uaa.web.AuthorizationManagersUtils.anyOf;

@Configuration
@EnableWebSecurity
class LoginSecurityConfiguration {

    private static final CsrfAwareEntryPointAndDeniedHandler LOGIN_ENTRYPOINT = new CsrfAwareEntryPointAndDeniedHandler("/invalid_request", "/login?error=invalid_login_request");
    private static final CsrfAwareEntryPointAndDeniedHandler ACCESS_DENIED_HANDLER = LOGIN_ENTRYPOINT;
    private static final Customizer<ExceptionHandlingConfigurer<HttpSecurity>> EXCEPTION_HANDLING = exceptionHandling -> {
        exceptionHandling.accessDeniedHandler(ACCESS_DENIED_HANDLER);
        exceptionHandling.authenticationEntryPoint(LOGIN_ENTRYPOINT);
    };

    @Bean
    ResourcePropertySource messagePropertiesSource() throws IOException {
        return new ResourcePropertySource("messages.properties");
    }

    @Bean
    @Order(FilterChainOrder.AUTOLOGIN_CODE)
    UaaFilterChain autologinCode(
            HttpSecurity http,
            CookieBasedCsrfTokenRepository csrfTokenRepository,
            @Qualifier("autologinAuthenticationFilter") AuthzAuthenticationFilter autologinFilter
    ) throws Exception {
        var autologinMatcher = new UaaRequestMatcher("/autologin");
        autologinMatcher.setParameters(Map.of("code", ""));

        var oauthAuthorizeMatcher = new UaaRequestMatcher("/oauth/authorize");
        oauthAuthorizeMatcher.setParameters(
                Map.of(
                        "response_type", "code",
                        "code", ""
                )
        );

        var originalChain = http
                .securityMatchers(matchers -> matchers.requestMatchers(autologinMatcher, oauthAuthorizeMatcher))
                .anonymous(AnonymousConfigurer::disable)
                .csrf(csrf -> {
                    csrf.ignoringRequestMatchers("/autologin");
                    csrf.csrfTokenRepository(csrfTokenRepository);
                })
                .addFilterAt(autologinFilter, UsernamePasswordAuthenticationFilter.class)
                .headers(headers -> headers.xssProtection(xss -> xss.disable()))
                .exceptionHandling(EXCEPTION_HANDLING)
                .build();
        return new UaaFilterChain(originalChain);
    }

    @Bean
    @Order(FilterChainOrder.AUTOLOGIN)
    UaaFilterChain autologin(
            HttpSecurity http,
            @Qualifier("basicAuthenticationEntryPoint") AuthenticationEntryPoint authenticationEntryPoint,
            @Qualifier("clientAuthenticationFilter") ClientBasicAuthenticationFilter clientBasicAuthenticationFilter
    ) throws Exception {
        var emptyAuthenticationManager = new ProviderManager(new AuthenticationManagerBeanDefinitionParser.NullAuthenticationProvider());
        var originalChain = http
                .securityMatcher("/autologin")
                .authenticationManager(emptyAuthenticationManager)
                .authorizeHttpRequests(req -> req.anyRequest().fullyAuthenticated())
                .anonymous(AnonymousConfigurer::disable)
                .csrf(CsrfConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(clientBasicAuthenticationFilter, BasicAuthenticationFilter.class)
                .exceptionHandling(exception -> exception.authenticationEntryPoint(authenticationEntryPoint))
                .headers(headers -> headers.xssProtection(xss -> xss.disable()))
                .build();
        return new UaaFilterChain(originalChain);
    }

    @Bean
    @Order(FilterChainOrder.INVITATIONS)
    UaaFilterChain invitation(
            HttpSecurity http,
            CookieBasedCsrfTokenRepository csrfTokenRepository
    ) throws Exception {
        var originalChain = http
                .securityMatcher(
                        "/invitations/**"
                )
                .authorizeHttpRequests(auth -> {
                    auth.requestMatchers(HttpMethod.GET, "/invitations/accept").access(anyOf().anonymous().fullyAuthenticated());
                    auth.requestMatchers(HttpMethod.POST, "/invitations/accept.do").hasAuthority("uaa.invited");
                    auth.requestMatchers(HttpMethod.POST, "/invitations/accept_enterprise.do").hasAuthority("uaa.invited");
                    auth.anyRequest().denyAll();

                })
                .securityContext(securityContext -> {
                    var securityContextRepository = new HttpSessionSecurityContextRepository();
                    securityContextRepository.setTrustResolver(new InvitationsAuthenticationTrustResolver());
                    securityContext.securityContextRepository(securityContextRepository);
                })
                .csrf(csrf -> csrf.csrfTokenRepository(csrfTokenRepository))
                .headers(headers -> headers.xssProtection(xss -> xss.disable()))
                .exceptionHandling(EXCEPTION_HANDLING)
                .build();
        return new UaaFilterChain(originalChain);
    }


    @Bean
    @Order(FilterChainOrder.INVITE)
    UaaFilterChain inviteUser(
            HttpSecurity http,
            @Qualifier("resourceAgnosticAuthenticationFilter") OAuth2AuthenticationProcessingFilter oauth2ResourceFilter
    ) throws Exception {
        var originalChain = http
                .securityMatcher("/invite_users/**")
                .authorizeHttpRequests(auth -> {
                    auth.requestMatchers(HttpMethod.POST, "/**").access(
                            anyOf().isUaaAdmin()
                                    .isZoneAdmin()
                                    .hasScope("scim.invite")
                    );

                    auth.anyRequest().denyAll();
                })
                .addFilterBefore(oauth2ResourceFilter, AbstractPreAuthenticatedProcessingFilter.class)
                .csrf(CsrfConfigurer::disable)
                .headers(headers -> headers.xssProtection(xss -> xss.disable()))
                .exceptionHandling(exception -> {
                    var authenticationEntryPoint = new OAuth2AuthenticationEntryPoint();
                    authenticationEntryPoint.setRealmName("UAA/oauth");
                    exception.authenticationEntryPoint(authenticationEntryPoint);
                    exception.accessDeniedHandler(new OAuth2AccessDeniedHandler());
                })
                .build();
        return new UaaFilterChain(originalChain);
    }

    @Bean
    @Order(FilterChainOrder.LOGIN_PUBLIC_OPERATIONS)
    UaaFilterChain loginPublicOperations(
            HttpSecurity http,
            DisableUserManagementSecurityFilter disableUserManagementSecurityFilter,
            ResetPasswordAuthenticationFilter resetPasswordAuthenticationFilter,
            CookieBasedCsrfTokenRepository csrfTokenRepository
    ) throws Exception {
        var originalChain = http
                .securityMatcher(
                        "/delete_saved_account",
                        "/verify_user",
                        "/verify_email",
                        "/forgot_password",
                        "/forgot_password.do",
                        ResetPasswordAuthenticationFilter.RESET_PASSWORD_URL
                )
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                .csrf(csrf -> {
                    csrf.ignoringRequestMatchers("/forgot_password.do");
                    csrf.csrfTokenRepository(csrfTokenRepository);
                })
                .headers(headers -> headers.xssProtection(xss -> xss.disable()))
                .addFilterBefore(disableUserManagementSecurityFilter, AnonymousAuthenticationFilter.class)
                .addFilterAfter(resetPasswordAuthenticationFilter, AuthorizationFilter.class)
                .exceptionHandling(EXCEPTION_HANDLING)
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
            LogoutFilter logoutFilter,
            CookieBasedCsrfTokenRepository csrfTokenRepository,
            AccountSavingAuthenticationSuccessHandler loginSuccessHandler,
            UaaAuthenticationFailureHandler loginFailureHandler
    ) throws Exception {
        var clientRedirectStateCache = new UaaSavedRequestCache();
        clientRedirectStateCache.setRequestMatcher(new AntPathRequestMatcher("/oauth/authorize**"));

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
                    auth.requestMatchers("/login**").access(anyOf().anonymous().fullyAuthenticated());
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
                .addFilterBefore(new PasswordChangeUiRequiredFilter(), UsernamePasswordAuthenticationFilter.class)
                .addFilterAt(logoutFilter, LogoutFilter.class)
                .exceptionHandling(EXCEPTION_HANDLING)
                .requestCache(cache -> cache.requestCache(clientRedirectStateCache))
                .headers(headers -> headers.xssProtection(xss -> xss.disable()))
                .build();
        return new UaaFilterChain(originalChain);
    }

    @Bean
    AuthzAuthenticationFilter autologinAuthenticationFilter(
            @Qualifier("autologinAuthenticationManager") AuthenticationManager authenticationManager,
            AccountSavingAuthenticationSuccessHandler loginSuccessHandler
    ) {
        var filter = new AuthzAuthenticationFilter(authenticationManager);
        filter.setParameterNames(List.of("code", "response_type"));
        filter.setMethods(Set.of(HttpMethod.GET.name(), HttpMethod.POST.name()));
        filter.setSuccessHandler(loginSuccessHandler);
        return filter;
    }


    /**
     * Handles a Logout click from the user, removes the Authentication object,
     * and determines if an OAuth2 or SAML2 Logout should be performed.
     * If Saml, it forwards a Saml2LogoutRequest to IDP/asserting party if configured.
     */
    @Bean
    LogoutFilter logoutFilter(
            UaaDelegatingLogoutSuccessHandler delegatingLogoutSuccessHandler,
            UaaAuthenticationFailureHandler authenticationFailureHandler,
            CookieBasedCsrfTokenRepository loginCookieCsrfRepository
    ) {

        SecurityContextLogoutHandler securityContextLogoutHandlerWithHandler = new SecurityContextLogoutHandler();
        CsrfLogoutHandler csrfLogoutHandler = new CsrfLogoutHandler(loginCookieCsrfRepository);
        CookieClearingLogoutHandler cookieClearingLogoutHandlerWithHandler = new CookieClearingLogoutHandler("JSESSIONID");

        LogoutFilter logoutFilter = new LogoutFilter(
                delegatingLogoutSuccessHandler,
                authenticationFailureHandler,
                securityContextLogoutHandlerWithHandler,
                csrfLogoutHandler,
                cookieClearingLogoutHandlerWithHandler
        );
        logoutFilter.setLogoutRequestMatcher(new AntPathRequestMatcher("/logout.do"));

        return logoutFilter;
    }

}
