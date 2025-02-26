package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.account.ResetPasswordAuthenticationFilter;
import org.cloudfoundry.identity.uaa.authentication.PasswordChangeUiRequiredFilter;
import org.cloudfoundry.identity.uaa.authentication.ReAuthenticationRequiredFilter;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetailsSource;
import org.cloudfoundry.identity.uaa.invitations.InvitationsAuthenticationTrustResolver;
import org.cloudfoundry.identity.uaa.oauth.provider.authentication.OAuth2AuthenticationProcessingFilter;
import org.cloudfoundry.identity.uaa.oauth.provider.error.OAuth2AccessDeniedHandler;
import org.cloudfoundry.identity.uaa.oauth.provider.error.OAuth2AuthenticationEntryPoint;
import org.cloudfoundry.identity.uaa.scim.DisableUserManagementSecurityFilter;
import org.cloudfoundry.identity.uaa.security.ContextSensitiveOAuth2SecurityExpressionMethods;
import org.cloudfoundry.identity.uaa.security.CsrfAwareEntryPointAndDeniedHandler;
import org.cloudfoundry.identity.uaa.security.web.CookieBasedCsrfTokenRepository;
import org.cloudfoundry.identity.uaa.security.web.HttpsHeaderFilter;
import org.cloudfoundry.identity.uaa.web.FilterChainOrder;
import org.cloudfoundry.identity.uaa.web.UaaFilterChain;
import org.cloudfoundry.identity.uaa.web.UaaSavedRequestCache;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.support.ResourcePropertySource;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
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
                    auth.requestMatchers(HttpMethod.GET, "/invitations/accept").access(anonymousOrFullyAuthenticated());
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
                .exceptionHandling(exception -> {
                    var authenticationEntryPoint = new CsrfAwareEntryPointAndDeniedHandler("/invalid_request", "/login?error=invalid_login_request");
                    exception.authenticationEntryPoint(authenticationEntryPoint);
                    exception.accessDeniedHandler(authenticationEntryPoint);
                })
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
                            (authSup, ctx) -> {
                                // TODO: dgarnier move to AuthorizationManagersUtils
                                var methods = new ContextSensitiveOAuth2SecurityExpressionMethods(authSup.get(), IdentityZone.getUaa());
                                var authorization = methods.hasAnyScope("scim.invite") || methods.hasScopeInAuthZone("zones.{zone.id}.admin");
                                return new AuthorizationDecision(authorization);
                            }
                    );
                    auth.anyRequest().denyAll();
                })
                .addFilterBefore(oauth2ResourceFilter, AbstractPreAuthenticatedProcessingFilter.class)
                .csrf(CsrfConfigurer::disable)
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
    @Order(FilterChainOrder.RESET_PASSWORD)
    UaaFilterChain resetPassword(
            HttpSecurity http,
            DisableUserManagementSecurityFilter disableUserManagementSecurityFilter,
            ResetPasswordAuthenticationFilter resetPasswordAuthenticationFilter,
            CookieBasedCsrfTokenRepository csrfTokenRepository
    ) throws Exception {
        var originalChain = http
                .securityMatcher("/reset_password.do")
                .addFilterBefore(disableUserManagementSecurityFilter, AnonymousAuthenticationFilter.class)
                .addFilterAfter(resetPasswordAuthenticationFilter, AuthorizationFilter.class)
                .csrf(csrf -> csrf.csrfTokenRepository(csrfTokenRepository))
                .exceptionHandling(exception -> {
                    var authenticationEntryPoint = new CsrfAwareEntryPointAndDeniedHandler("/invalid_request", "/login?error=invalid_login_request");
                    exception.authenticationEntryPoint(authenticationEntryPoint);
                    exception.accessDeniedHandler(authenticationEntryPoint);
                })
                .build();
        return new UaaFilterChain(originalChain);
    }

    @Bean
    @Order(FilterChainOrder.FORGOT_PASSWORD)
    UaaFilterChain forgotPassword(HttpSecurity http) throws Exception {
        var originalChain = http
                .securityMatcher(
                        "/forgot_password",
                        "/forgot_password.do"
                )
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                .csrf(CsrfConfigurer::disable)
                .exceptionHandling(exception -> {
                    exception.authenticationEntryPoint(new CsrfAwareEntryPointAndDeniedHandler("/invalid_request", "/login?error=invalid_login_request"));
                })
                .build();
        return new UaaFilterChain(originalChain);
    }

    @Bean
    @Order(FilterChainOrder.DELETE_SAVED_ACCOUNT)
    UaaFilterChain deleteSavedAccount(
            HttpSecurity http,
            @Qualifier("clientAuthenticationManager") AuthenticationManager authenticationManager,
            @Qualifier("basicAuthenticationEntryPoint") AuthenticationEntryPoint authenticationEntryPoint
    ) throws Exception {
        var originalChain = http
                .securityMatcher("/delete_saved_account")
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                .authenticationManager(authenticationManager)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling(exception -> {
                    exception.authenticationEntryPoint(authenticationEntryPoint);
                })
                .build();
        return new UaaFilterChain(originalChain);
    }

    @Bean
    @Order(FilterChainOrder.VERIFY_EMAIL)
    UaaFilterChain verifyEmail(HttpSecurity http) throws Exception {
        var originalChain = http
                .securityMatcher("/verify_email")
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                .csrf(CsrfConfigurer::disable)
                .exceptionHandling(exception -> {
                    exception.authenticationEntryPoint(new CsrfAwareEntryPointAndDeniedHandler("/invalid_request", "/login?error=invalid_login_request"));
                })
                .build();
        return new UaaFilterChain(originalChain);
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
