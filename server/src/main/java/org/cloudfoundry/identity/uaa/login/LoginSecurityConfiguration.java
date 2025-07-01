package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.account.ResetPasswordAuthenticationFilter;
import org.cloudfoundry.identity.uaa.account.ResetPasswordService;
import org.cloudfoundry.identity.uaa.authentication.AuthzAuthenticationFilter;
import org.cloudfoundry.identity.uaa.authentication.ClientBasicAuthenticationFilter;
import org.cloudfoundry.identity.uaa.authentication.LoginClientParametersAuthenticationFilter;
import org.cloudfoundry.identity.uaa.authentication.LoginServerTokenEndpointFilter;
import org.cloudfoundry.identity.uaa.authentication.PasswordChangeUiRequiredFilter;
import org.cloudfoundry.identity.uaa.authentication.ReAuthenticationRequiredFilter;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetailsSource;
import org.cloudfoundry.identity.uaa.authentication.manager.LoginAuthenticationManager;
import org.cloudfoundry.identity.uaa.authentication.manager.ScopeAuthenticationFilter;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.invitations.InvitationsAuthenticationTrustResolver;
import org.cloudfoundry.identity.uaa.oauth.UaaTokenServices;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2RequestFactory;
import org.cloudfoundry.identity.uaa.oauth.provider.authentication.OAuth2AuthenticationManager;
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
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.support.ResourcePropertySource;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.lang.Nullable;
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
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.session.DisableEncodeUrlFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

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
    private final UaaTokenServices tokenServices;
    private final OAuth2AccessDeniedHandler oauthAccessDeniedHandler;
    private final OAuth2AuthenticationEntryPoint oauthAuthenticationEntryPoint;
    private final AuthzAuthenticationFilter loginAuthenticationFilter;
    private final AuthenticationManager loginAuthenticationManager;
    private final ScopeAuthenticationFilter scopeAuthenticationFilter;

    public LoginSecurityConfiguration(
            UaaTokenServices tokenServices,
            @Qualifier("oauthAuthenticationEntryPoint") OAuth2AuthenticationEntryPoint oauthAuthenticationEntryPoint,
            @Qualifier("oauthAccessDeniedHandler") OAuth2AccessDeniedHandler oauthAccessDeniedHandler,
            LoginAuthenticationManager loginAuthenticationManager
    ) {
        ScopeAuthenticationFilter scopeAuthenticationFilter = new ScopeAuthenticationFilter();
        this.tokenServices = tokenServices;
        this.oauthAuthenticationEntryPoint = oauthAuthenticationEntryPoint;
        this.oauthAccessDeniedHandler = oauthAccessDeniedHandler;
        this.loginAuthenticationManager = loginAuthenticationManager;

        this.loginAuthenticationFilter = new AuthzAuthenticationFilter(loginAuthenticationManager);
        this.scopeAuthenticationFilter = scopeAuthenticationFilter;
        this.loginAuthenticationFilter.setParameterNames(List.of(
                "login",
                "username",
                "user_id",
                "origin",
                "given_name",
                "family_name",
                "email",
                "authorities"
        ));
    }

    @Bean
    public FilterRegistrationBean<ResetPasswordAuthenticationFilter> resetPasswordAuthenticationFilter(
            ResetPasswordService service,
            ExpiringCodeStore expiringCodeStore
    )
    {
        ResetPasswordAuthenticationFilter filter = new ResetPasswordAuthenticationFilter(service, expiringCodeStore);
        FilterRegistrationBean<ResetPasswordAuthenticationFilter> bean = new FilterRegistrationBean<>(filter);
        bean.setEnabled(false);
        return bean;
    }

    @Bean
    ResourcePropertySource messagePropertiesSource() throws IOException {
        return new ResourcePropertySource("messages.properties");
    }

    @Bean
    @Order(FilterChainOrder.AUTHENTICATE_BEARER)
    UaaFilterChain authenticateBearer(
            HttpSecurity http
    ) throws Exception {
        var requestMatcher = new UaaRequestMatcher("/authenticate");
        requestMatcher.setAccept(List.of(MediaType.APPLICATION_JSON_VALUE));
        requestMatcher.setHeaders(Map.of("Authorization", List.of("bearer ")));
        var originalChain = http
                .securityMatcher(requestMatcher)
                .authorizeHttpRequests(auth -> auth.anyRequest().fullyAuthenticated())
                .authenticationManager(loginAuthenticationManager)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.NEVER))
                .addFilterBefore(oauth2ResourceFilter("oauth"), AbstractPreAuthenticatedProcessingFilter.class)
                .addFilterBefore(scopeAuthenticationFilter, AbstractPreAuthenticatedProcessingFilter.class)
                .exceptionHandling(exception -> {
                    exception.authenticationEntryPoint(oauthAuthenticationEntryPoint);
                    exception.accessDeniedHandler(oauthAccessDeniedHandler);
                })
                .csrf(CsrfConfigurer::disable)
                .anonymous(AnonymousConfigurer::disable)
                .securityContext(sc -> sc.requireExplicitSave(false))
                .build();
        return new UaaFilterChain(originalChain, "authenticateCatchAll");

    }

    /**
     * This used to be a fully "disable security" on XML. There is no way to do this with
     * Spring Security itself, you would have to use a {@link WebMvcConfigurer}. However,
     * it would take precedence over other filter chains that deal with the {@code /authenticate}
     * endpoint.
     * <p>
     * Here, we are creating a simple, passthrough filter chain, disabling CSRF in the process.
     */
    @Bean
    @Order(FilterChainOrder.AUTHENTICATE_CATCH_ALL)
    UaaFilterChain authenticateCatchAll(HttpSecurity http) throws Exception {
        var originalChain = http
                .securityMatcher("/authenticate/**")
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                .csrf(CsrfConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .securityContext(sc -> sc.requireExplicitSave(false))
                .build();
        return new UaaFilterChain(originalChain, "authenticateCatchAll");
    }

    @Bean
    @Order(FilterChainOrder.LOGIN_AUTHORIZE)
    UaaFilterChain loginAuthorize(
            HttpSecurity http
    ) throws Exception {
        var requestMatcher = new UaaRequestMatcher("/oauth/authorize");
        requestMatcher.setAccept(List.of(MediaType.APPLICATION_JSON_VALUE));
        requestMatcher.setParameters(Map.of("source", "login"));
        var originalChain = http
                .securityMatcher(requestMatcher)
                .authorizeHttpRequests(auth -> auth.anyRequest().fullyAuthenticated())
                .authenticationManager(loginAuthenticationManager)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.NEVER))
                .addFilterBefore(oauth2ResourceFilter("oauth"), AbstractPreAuthenticatedProcessingFilter.class)
                .addFilterBefore(scopeAuthenticationFilter, AbstractPreAuthenticatedProcessingFilter.class)
                .addFilterBefore(loginAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .exceptionHandling(exception -> {
                    exception.authenticationEntryPoint(oauthAuthenticationEntryPoint);
                    exception.accessDeniedHandler(oauthAccessDeniedHandler);
                })
                .csrf(CsrfConfigurer::disable)
                .anonymous(AnonymousConfigurer::disable)
                .securityContext(sc -> sc.requireExplicitSave(false))
                .build();
        return new UaaFilterChain(originalChain, "loginAuthorize");
    }

    @Bean
    @Order(FilterChainOrder.LOGIN_TOKEN)
    UaaFilterChain loginToken(
            HttpSecurity http,
            @Qualifier("clientAuthenticationManager") AuthenticationManager authenticationManager,
            LoginAuthenticationManager loginAuthenticationManager,
            OAuth2RequestFactory oAuth2RequestFactory,
            UaaAuthenticationDetailsSource authenticationDetailsSource
    ) throws Exception {
        LoginClientParametersAuthenticationFilter loginClientParametersAuthenticationFilter =
                new LoginClientParametersAuthenticationFilter(authenticationManager);
        LoginServerTokenEndpointFilter loginFilter = new LoginServerTokenEndpointFilter(
                loginAuthenticationManager, oAuth2RequestFactory, authenticationDetailsSource
        );
        var requestMatcher = new UaaRequestMatcher("/oauth/token");
        requestMatcher.setAccept(List.of(MediaType.APPLICATION_JSON_VALUE));
        requestMatcher.setHeaders(Map.of("Authorization", List.of("bearer ")));
        requestMatcher.setParameters(Map.of(
                "source", "login",
                "grant_type", "password",
                "add_new", ""
        ));
        var originalChain = http
                .securityMatcher(requestMatcher)
                .authorizeHttpRequests(auth -> auth.anyRequest().fullyAuthenticated())
                .authenticationManager(loginAuthenticationManager)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.NEVER))
                .addFilterBefore(oauth2ResourceFilter("oauth"), AbstractPreAuthenticatedProcessingFilter.class)
                .addFilterBefore(scopeAuthenticationFilter, AbstractPreAuthenticatedProcessingFilter.class)
                .addFilterBefore(loginClientParametersAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(loginFilter, BasicAuthenticationFilter.class)
                .exceptionHandling(exception -> {
                    exception.authenticationEntryPoint(oauthAuthenticationEntryPoint);
                    exception.accessDeniedHandler(oauthAccessDeniedHandler);
                })
                .csrf(CsrfConfigurer::disable)
                .anonymous(AnonymousConfigurer::disable)
                .securityContext(sc -> sc.requireExplicitSave(false))
                .build();
        return new UaaFilterChain(originalChain, "loginToken");
    }

    @Bean
    @Order(FilterChainOrder.LOGIN_AUTHORIZE_OLD)
    UaaFilterChain loginAuthorizeOld(HttpSecurity http) throws Exception {
        var requestMatcher = new UaaRequestMatcher("/oauth/authorize");
        requestMatcher.setAccept(List.of(MediaType.APPLICATION_JSON_VALUE));
        requestMatcher.setParameters(Map.of("login", "{"));

        var originalFilterChain = http
                .securityMatcher(requestMatcher)
                .authorizeHttpRequests(auth -> auth.anyRequest().fullyAuthenticated())
                .authenticationManager(loginAuthenticationManager)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.ALWAYS))
                .addFilterBefore(loginAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(oauth2ResourceFilter("oauth"), AbstractPreAuthenticatedProcessingFilter.class)
                .csrf(CsrfConfigurer::disable)
                .anonymous(AnonymousConfigurer::disable)
                .exceptionHandling(exception -> {
                    exception.authenticationEntryPoint(oauthAuthenticationEntryPoint);
                    exception.accessDeniedHandler(oauthAccessDeniedHandler);
                })
                .securityContext(sc -> sc.requireExplicitSave(false))
                .build();
        return new UaaFilterChain(originalFilterChain, "loginAuthorizeOld");
    }

    @Bean
    @Order(FilterChainOrder.LOGIN_PASSWORD)
    UaaFilterChain password(HttpSecurity http) throws Exception {
        // TODO: remove
        var emptyAuthenticationManager = new ProviderManager(new AuthenticationManagerBeanDefinitionParser.NullAuthenticationProvider());

        var originalFilterChain = http
                .securityMatcher("/password_*")
                .authorizeHttpRequests(auth -> auth.requestMatchers("/password_*").access(
                        anyOf()
                                .isZoneAdmin()
                                .hasScope("oauth.login")
                                .throwOnMissingScope()
                ))
                .authenticationManager(emptyAuthenticationManager)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(oauth2ResourceFilter(null), AbstractPreAuthenticatedProcessingFilter.class)
                .csrf(CsrfConfigurer::disable)
                .anonymous(AnonymousConfigurer::disable)
                .exceptionHandling(exception -> {
                    exception.authenticationEntryPoint(oauthAuthenticationEntryPoint);
                    exception.accessDeniedHandler(oauthAccessDeniedHandler);
                })
                .securityContext(sc -> sc.requireExplicitSave(false))
                .build();

        return new UaaFilterChain(originalFilterChain, "password");
    }

    @Bean
    @Order(FilterChainOrder.EMAIL)
    UaaFilterChain email(HttpSecurity http) throws Exception {
        // TODO: remove
        var emptyAuthenticationManager = new ProviderManager(new AuthenticationManagerBeanDefinitionParser.NullAuthenticationProvider());

        var originalFilterChain = http
                .securityMatcher("/email_*")
                .authorizeHttpRequests(auth -> auth.requestMatchers("/email_*").access(
                        anyOf()
                                .hasScope("oauth.login")
                                .throwOnMissingScope()
                ))
                .authenticationManager(emptyAuthenticationManager)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(oauth2ResourceFilter(null), AbstractPreAuthenticatedProcessingFilter.class)
                .csrf(CsrfConfigurer::disable)
                .anonymous(AnonymousConfigurer::disable)
                .exceptionHandling(exception -> {
                    exception.authenticationEntryPoint(oauthAuthenticationEntryPoint);
                    exception.accessDeniedHandler(oauthAccessDeniedHandler);
                })
                .securityContext(sc -> sc.requireExplicitSave(false))
                .build();

        return new UaaFilterChain(originalFilterChain, "email");
    }

    @Bean
    @Order(FilterChainOrder.AUTOLOGIN_CODE)
    UaaFilterChain autologinCode(
            HttpSecurity http,
            CookieBasedCsrfTokenRepository csrfTokenRepository,
            @Qualifier("autologinAuthenticationManager") AuthenticationManager authenticationManager,
            AccountSavingAuthenticationSuccessHandler loginSuccessHandler
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

        var autologinFilter = new AuthzAuthenticationFilter(authenticationManager);
        autologinFilter.setParameterNames(List.of("code", "response_type"));
        autologinFilter.setMethods(Set.of(HttpMethod.GET.name(), HttpMethod.POST.name()));
        autologinFilter.setSuccessHandler(loginSuccessHandler);

        var originalChain = http
                .securityMatchers(matchers -> matchers.requestMatchers(autologinMatcher, oauthAuthorizeMatcher))
                .anonymous(AnonymousConfigurer::disable)
                .csrf(csrf -> {
                    csrf.ignoringRequestMatchers("/autologin");
                    csrf.csrfTokenRepository(csrfTokenRepository);
                    csrf.csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler());
                })
                .addFilterAt(autologinFilter, UsernamePasswordAuthenticationFilter.class)
                .headers(headers -> headers.xssProtection(xss -> xss.disable()))
                .exceptionHandling(EXCEPTION_HANDLING)
                .securityContext(sc -> sc.requireExplicitSave(false))
                .build();
        return new UaaFilterChain(originalChain, "autologinCode");
    }

    @Bean
    @Order(FilterChainOrder.AUTOLOGIN)
    UaaFilterChain autologin(
            HttpSecurity http,
            @Qualifier("basicAuthenticationEntryPoint") AuthenticationEntryPoint authenticationEntryPoint,
            @Qualifier("clientAuthenticationFilter") FilterRegistrationBean<ClientBasicAuthenticationFilter> clientBasicAuthenticationFilter
    ) throws Exception {
        var emptyAuthenticationManager = new ProviderManager(new AuthenticationManagerBeanDefinitionParser.NullAuthenticationProvider());
        var originalChain = http
                .securityMatcher("/autologin")
                .authenticationManager(emptyAuthenticationManager)
                .authorizeHttpRequests(req -> req.anyRequest().fullyAuthenticated())
                .anonymous(AnonymousConfigurer::disable)
                .csrf(CsrfConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(clientBasicAuthenticationFilter.getFilter(), BasicAuthenticationFilter.class)
                .exceptionHandling(exception -> exception.authenticationEntryPoint(authenticationEntryPoint))
                .headers(headers -> headers.xssProtection(xss -> xss.disable()))
                .securityContext(sc -> sc.requireExplicitSave(false))
                .build();
        return new UaaFilterChain(originalChain, "autologin");
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
                    securityContext.requireExplicitSave(false);
                })
                .csrf(csrf -> {
                    csrf.csrfTokenRepository(csrfTokenRepository);
                    csrf.csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler());
                })
                .headers(headers -> headers.xssProtection(xss -> xss.disable()))
                .exceptionHandling(EXCEPTION_HANDLING)
                .build();
        return new UaaFilterChain(originalChain, "invitation");
    }


    @Bean
    @Order(FilterChainOrder.INVITE)
    UaaFilterChain inviteUser(
            HttpSecurity http,
            @Qualifier("resourceAgnosticAuthenticationFilter") FilterRegistrationBean<OAuth2AuthenticationProcessingFilter> oauth2ResourceFilter
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
                .addFilterBefore(oauth2ResourceFilter.getFilter(), AbstractPreAuthenticatedProcessingFilter.class)
                .csrf(CsrfConfigurer::disable)
                .headers(headers -> headers.xssProtection(xss -> xss.disable()))
                .exceptionHandling(exception -> {
                    var authenticationEntryPoint = new OAuth2AuthenticationEntryPoint();
                    authenticationEntryPoint.setRealmName("UAA/oauth");
                    exception.authenticationEntryPoint(authenticationEntryPoint);
                    exception.accessDeniedHandler(new OAuth2AccessDeniedHandler());
                })
                .securityContext(sc -> sc.requireExplicitSave(false))
                .build();
        return new UaaFilterChain(originalChain, "inviteUser");
    }

    @Bean
    @Order(FilterChainOrder.LOGIN_PUBLIC_OPERATIONS)
    UaaFilterChain loginPublicOperations(
            HttpSecurity http,
            FilterRegistrationBean<DisableUserManagementSecurityFilter> disableUserManagementSecurityFilter,
            FilterRegistrationBean<ResetPasswordAuthenticationFilter> resetPasswordAuthenticationFilter,
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
                    csrf.csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler());
                })
                .headers(headers -> headers.xssProtection(xss -> xss.disable()))
                .addFilterBefore(disableUserManagementSecurityFilter.getFilter(), AnonymousAuthenticationFilter.class)
                .addFilterAfter(resetPasswordAuthenticationFilter.getFilter(), AuthorizationFilter.class)
                .exceptionHandling(EXCEPTION_HANDLING)
                .securityContext(sc -> sc.requireExplicitSave(false))
                .build();
        return new UaaFilterChain(originalChain,"loginPublicOperations");
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
            final @Qualifier("samlEntityID") String samlEntityID,
            FilterRegistrationBean<LogoutFilter> logoutFilter,
            CookieBasedCsrfTokenRepository csrfTokenRepository,
            AccountSavingAuthenticationSuccessHandler loginSuccessHandler,
            UaaAuthenticationFailureHandler loginFailureHandler
    ) throws Exception {
        ReAuthenticationRequiredFilter reAuthenticationRequiredFilter = new ReAuthenticationRequiredFilter(samlEntityID);
        var clientRedirectStateCache = new UaaSavedRequestCache();
        clientRedirectStateCache.setRequestMatcher(new AntPathRequestMatcher("/oauth/authorize**"));

        // See: https://docs.spring.io/spring-security/reference/servlet/exploits/csrf.html#migrating-to-spring-security-6
        var csrfRequestHandler = new CsrfTokenRequestAttributeHandler();
        csrfRequestHandler.setCsrfRequestAttributeName(null);
        var originalChain = http
                .csrf(csrf -> {
                    csrf.csrfTokenRepository(csrfTokenRepository);
                    csrf.csrfTokenRequestHandler(csrfRequestHandler);
                })
                .authenticationManager(authenticationManager)
                .authorizeHttpRequests(auth -> {
                    auth.requestMatchers("/force_password_change/**").fullyAuthenticated();
                    auth.requestMatchers("/reset_password**").anonymous();
                    auth.requestMatchers("/create_account*").anonymous();
                    auth.requestMatchers("/login/idp_discovery").anonymous();
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
                .addFilterAt(logoutFilter.getFilter(), LogoutFilter.class)
                .exceptionHandling(EXCEPTION_HANDLING)
                .requestCache(cache -> cache.requestCache(clientRedirectStateCache))
                .headers(headers -> headers.xssProtection(xss -> xss.disable()))
                .securityContext(sc -> sc.requireExplicitSave(false))
                .build();
        return new UaaFilterChain(originalChain, "uiSecurity");
    }

    /**
     * Handles a Logout click from the user, removes the Authentication object,
     * and determines if an OAuth2 or SAML2 Logout should be performed.
     * If Saml, it forwards a Saml2LogoutRequest to IDP/asserting party if configured.
     */
    @Bean
    FilterRegistrationBean<LogoutFilter> logoutFilter(
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
        FilterRegistrationBean<LogoutFilter> bean = new FilterRegistrationBean<>(logoutFilter);
        bean.setEnabled(false);
        return bean;
    }

    public OAuth2AuthenticationProcessingFilter oauth2ResourceFilter(@Nullable String resourceId) {
        var oauth2AuthenticationManager = new OAuth2AuthenticationManager();
        oauth2AuthenticationManager.setTokenServices(tokenServices);
        if (resourceId != null) {
            oauth2AuthenticationManager.setResourceId(resourceId);
        }
        var oauth2ResourceFilter = new OAuth2AuthenticationProcessingFilter();
        oauth2ResourceFilter.setAuthenticationManager(oauth2AuthenticationManager);
        oauth2ResourceFilter.setAuthenticationEntryPoint(oauthAuthenticationEntryPoint);
        return oauth2ResourceFilter;
    }

}
