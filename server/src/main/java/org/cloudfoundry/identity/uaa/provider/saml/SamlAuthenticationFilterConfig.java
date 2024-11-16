package org.cloudfoundry.identity.uaa.provider.saml;

import org.cloudfoundry.identity.uaa.authentication.SamlLogoutRequestValidator;
import org.cloudfoundry.identity.uaa.authentication.SamlLogoutResponseValidator;
import org.cloudfoundry.identity.uaa.authentication.ZoneAwareWhitelistLogoutSuccessHandler;
import org.cloudfoundry.identity.uaa.login.UaaAuthenticationFailureHandler;
import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.oauth.ExternalOAuthLogoutSuccessHandler;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.security.web.CookieBasedCsrfTokenRepository;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.web.UaaSavedRequestAwareAuthenticationSuccessHandler;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequestValidator;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutResponseValidator;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.Saml2AuthenticationTokenConverter;
import org.springframework.security.saml2.provider.service.web.Saml2WebSsoAuthenticationRequestFilter;
import org.springframework.security.saml2.provider.service.web.authentication.OpenSaml4AuthenticationRequestResolver;
import org.springframework.security.saml2.provider.service.web.authentication.Saml2WebSsoAuthenticationFilter;
import org.springframework.security.saml2.provider.service.web.authentication.logout.OpenSaml4LogoutRequestResolver;
import org.springframework.security.saml2.provider.service.web.authentication.logout.OpenSaml4LogoutResponseResolver;
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2LogoutRequestFilter;
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2LogoutRequestResolver;
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2LogoutResponseFilter;
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2LogoutResponseResolver;
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2RelyingPartyInitiatedLogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.CookieClearingLogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.csrf.CsrfLogoutHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.Filter;

/**
 * Configuration for SAML Filters and Authentication Providers for SAML Authentication.
 */
@Configuration
public class SamlAuthenticationFilterConfig {

    public static final String BACKWARD_COMPATIBLE_ASSERTION_CONSUMER_FILTER_PROCESSES_URI = "/saml/SSO/alias/{registrationId}";

    /**
     * Handles building and forwarding the SAML2 Authentication Request to the IDP.
     */
    @Autowired
    @Bean
    Filter saml2WebSsoAuthenticationRequestFilter(RelyingPartyRegistrationResolver relyingPartyRegistrationResolver) {
        OpenSaml4AuthenticationRequestResolver openSaml4AuthenticationRequestResolver = new OpenSaml4AuthenticationRequestResolver(relyingPartyRegistrationResolver);

        return new Saml2WebSsoAuthenticationRequestFilter(openSaml4AuthenticationRequestResolver);
    }

    @Bean
    SecurityContextRepository securityContextRepository() {
        return new HttpSessionSecurityContextRepository();
    }

    @Autowired
    @Bean
    SamlUaaAuthenticationUserManager samlUaaAuthenticationUserManager(final UaaUserDatabase userDatabase,
                                                                      ApplicationEventPublisher applicationEventPublisher) {

        SamlUaaAuthenticationUserManager samlUaaAuthenticationUserManager = new SamlUaaAuthenticationUserManager(userDatabase);
        samlUaaAuthenticationUserManager.setApplicationEventPublisher(applicationEventPublisher);

        return samlUaaAuthenticationUserManager;
    }

    @Autowired
    @Bean
    AuthenticationProvider samlAuthenticationProvider(IdentityZoneManager identityZoneManager,
                                                      final JdbcIdentityProviderProvisioning identityProviderProvisioning,
                                                      ScimGroupExternalMembershipManager externalMembershipManager,
                                                      SamlUaaAuthenticationUserManager samlUaaAuthenticationUserManager,
                                                      ApplicationEventPublisher applicationEventPublisher,
                                                      SamlConfigProps samlConfigProps) {

        SamlUaaAuthenticationAttributesConverter attributesConverter = new SamlUaaAuthenticationAttributesConverter();
        SamlUaaAuthenticationAuthoritiesConverter authoritiesConverter = new SamlUaaAuthenticationAuthoritiesConverter(externalMembershipManager);

        SamlUaaResponseAuthenticationConverter samlResponseAuthenticationConverter =
                new SamlUaaResponseAuthenticationConverter(identityZoneManager, identityProviderProvisioning,
                        samlUaaAuthenticationUserManager, attributesConverter, authoritiesConverter);
        samlResponseAuthenticationConverter.setApplicationEventPublisher(applicationEventPublisher);

        OpenSaml4AuthenticationProvider samlResponseAuthenticationProvider = new OpenSaml4AuthenticationProvider();
        samlResponseAuthenticationProvider.setResponseAuthenticationConverter(samlResponseAuthenticationConverter);

        // This validator ignores wraps the default validator and ignores InResponseTo errors, if configured
        UaaInResponseToHandlingResponseValidator uaaInResponseToHandlingResponseValidator =
                new UaaInResponseToHandlingResponseValidator(OpenSaml4AuthenticationProvider.createDefaultResponseValidator(), samlConfigProps.getDisableInResponseToCheck());
        samlResponseAuthenticationProvider.setResponseValidator(uaaInResponseToHandlingResponseValidator);

        return samlResponseAuthenticationProvider;
    }

    /**
     * Handles the return SAML2 Authentication Response from the IDP and creates the Authentication object.
     */
    @Autowired
    @Bean
    Filter saml2WebSsoAuthenticationFilter(AuthenticationProvider samlAuthenticationProvider,
                                           UaaRelyingPartyRegistrationResolver relyingPartyRegistrationResolver,
                                           SecurityContextRepository securityContextRepository,
                                           SamlLoginAuthenticationFailureHandler samlLoginAuthenticationFailureHandler,
                                           UaaSavedRequestAwareAuthenticationSuccessHandler samlLoginAuthenticationSuccessHandler) {

        Saml2AuthenticationTokenConverter saml2AuthenticationTokenConverter = new Saml2AuthenticationTokenConverter((RelyingPartyRegistrationResolver)relyingPartyRegistrationResolver);
        Saml2WebSsoAuthenticationFilter saml2WebSsoAuthenticationFilter = new Saml2WebSsoAuthenticationFilter(saml2AuthenticationTokenConverter, BACKWARD_COMPATIBLE_ASSERTION_CONSUMER_FILTER_PROCESSES_URI);

        ProviderManager authenticationManager = new ProviderManager(samlAuthenticationProvider);
        saml2WebSsoAuthenticationFilter.setAuthenticationManager(authenticationManager);
        saml2WebSsoAuthenticationFilter.setSecurityContextRepository(securityContextRepository);
        saml2WebSsoAuthenticationFilter.setFilterProcessesUrl(BACKWARD_COMPATIBLE_ASSERTION_CONSUMER_FILTER_PROCESSES_URI);
        saml2WebSsoAuthenticationFilter.setAuthenticationFailureHandler(samlLoginAuthenticationFailureHandler);
        saml2WebSsoAuthenticationFilter.setAuthenticationSuccessHandler(samlLoginAuthenticationSuccessHandler);

        return saml2WebSsoAuthenticationFilter;
    }

    /**
     * Handler deciding where to redirect user after unsuccessful login
     */
    @Bean
    public SamlLoginAuthenticationFailureHandler samlLoginAuthenticationFailureHandler() {
        SamlLoginAuthenticationFailureHandler handler = new SamlLoginAuthenticationFailureHandler();
        handler.setDefaultFailureUrl("/saml_error");
        return handler;
    }

    /**
     * Handler deciding where to redirect user after successful login
     */
    @Bean
    public UaaSavedRequestAwareAuthenticationSuccessHandler successRedirectHandler() {
        return new UaaSavedRequestAwareAuthenticationSuccessHandler();
    }

    @Autowired
    @Bean
    Saml2LogoutRequestResolver saml2LogoutRequestResolver(RelyingPartyRegistrationResolver relyingPartyRegistrationResolver) {
        return new OpenSaml4LogoutRequestResolver(relyingPartyRegistrationResolver);
    }

    /**
     * Handles a Relying Party Initiated Logout
     * and forwards a Saml2LogoutRequest to IDP/asserting party if configured.
     */
    @Autowired
    @Bean
    Saml2RelyingPartyInitiatedLogoutSuccessHandler saml2RelyingPartyInitiatedLogoutSuccessHandler(Saml2LogoutRequestResolver logoutRequestResolver) {
        return new Saml2RelyingPartyInitiatedLogoutSuccessHandler(logoutRequestResolver);
    }

    @Autowired
    @Bean
    UaaDelegatingLogoutSuccessHandler uaaDelegatingLogoutSuccessHandler(ZoneAwareWhitelistLogoutSuccessHandler zoneAwareWhitelistLogoutHandler,
                                                                        Saml2RelyingPartyInitiatedLogoutSuccessHandler saml2RelyingPartyInitiatedLogoutSuccessHandler,
                                                                        ExternalOAuthLogoutSuccessHandler externalOAuthLogoutHandler,
                                                                        RelyingPartyRegistrationResolver relyingPartyRegistrationResolver) {

        return new UaaDelegatingLogoutSuccessHandler(zoneAwareWhitelistLogoutHandler,
                saml2RelyingPartyInitiatedLogoutSuccessHandler,
                externalOAuthLogoutHandler,
                relyingPartyRegistrationResolver);
    }

    /**
     * Handles a Logout click from the user, removes the Authentication object,
     * and determines if an OAuth2 or SAML2 Logout should be performed.
     * If Saml, it forwards a Saml2LogoutRequest to IDP/asserting party if configured.
     */
    @Autowired
    @Bean
    LogoutFilter logoutFilter(UaaDelegatingLogoutSuccessHandler delegatingLogoutSuccessHandler,
                              UaaAuthenticationFailureHandler authenticationFailureHandler,
                              CookieBasedCsrfTokenRepository loginCookieCsrfRepository) {

        SecurityContextLogoutHandler securityContextLogoutHandlerWithHandler = new SecurityContextLogoutHandler();
        CsrfLogoutHandler csrfLogoutHandler = new CsrfLogoutHandler(loginCookieCsrfRepository);
        CookieClearingLogoutHandler cookieClearingLogoutHandlerWithHandler = new CookieClearingLogoutHandler("JSESSIONID");

        LogoutFilter logoutFilter = new LogoutFilter(delegatingLogoutSuccessHandler,
                authenticationFailureHandler, securityContextLogoutHandlerWithHandler, csrfLogoutHandler,
                cookieClearingLogoutHandlerWithHandler);
        logoutFilter.setLogoutRequestMatcher(new AntPathRequestMatcher("/logout.do"));

        return logoutFilter;
    }

    /**
     * Handles a return SAML2LogoutResponse from IDP/asserting party in response to a Saml2LogoutRequest from UAA.
     */
    @Autowired
    @Bean
    Saml2LogoutResponseFilter saml2LogoutResponseFilter(RelyingPartyRegistrationResolver relyingPartyRegistrationResolver,
                                                        UaaDelegatingLogoutSuccessHandler successHandler) {

        // This validator ignores missing signatures in the SAML2 Logout Response
        Saml2LogoutResponseValidator openSamlLogoutResponseValidator = new SamlLogoutResponseValidator();

        Saml2LogoutResponseFilter saml2LogoutResponseFilter = new Saml2LogoutResponseFilter(relyingPartyRegistrationResolver, openSamlLogoutResponseValidator, successHandler);
        saml2LogoutResponseFilter.setLogoutRequestMatcher(new AntPathRequestMatcher("/saml/SingleLogout/alias/{registrationId}"));

        return saml2LogoutResponseFilter;
    }

    /**
     * Handles an incoming Saml2LogoutRequest from an Asserting Party Initiated Logout
     */
    @Autowired
    @Bean
    Saml2LogoutRequestFilter saml2LogoutRequestFilter(UaaRelyingPartyRegistrationResolver relyingPartyRegistrationResolver,
                                                      UaaAuthenticationFailureHandler authenticationFailureHandler,
                                                      CookieBasedCsrfTokenRepository loginCookieCsrfRepository) {

        // This validator ignores missing signatures in the SAML2 Logout Response
        Saml2LogoutRequestValidator logoutRequestValidator = new SamlLogoutRequestValidator();
        Saml2LogoutResponseResolver logoutResponseResolver = new OpenSaml4LogoutResponseResolver(relyingPartyRegistrationResolver);

        SecurityContextLogoutHandler securityContextLogoutHandlerWithHandler = new SecurityContextLogoutHandler();
        CsrfLogoutHandler csrfLogoutHandler = new CsrfLogoutHandler(loginCookieCsrfRepository);
        CookieClearingLogoutHandler cookieClearingLogoutHandlerWithHandler = new CookieClearingLogoutHandler("JSESSIONID");

        Saml2LogoutRequestFilter saml2LogoutRequestFilter = new Saml2LogoutRequestFilter(relyingPartyRegistrationResolver,
                logoutRequestValidator, logoutResponseResolver,
                authenticationFailureHandler, securityContextLogoutHandlerWithHandler, csrfLogoutHandler,
                cookieClearingLogoutHandlerWithHandler);
        saml2LogoutRequestFilter.setLogoutRequestMatcher(new AntPathRequestMatcher("/saml/SingleLogout/alias/{registrationId}"));
        return saml2LogoutRequestFilter;
    }

    /**
     * Handles Authentication for the Saml2 Bearer Grant.
     */
    @Autowired
    @Bean
    Saml2BearerGrantAuthenticationConverter samlBearerGrantAuthenticationProvider(IdentityZoneManager identityZoneManager,
                                                                                  final JdbcIdentityProviderProvisioning identityProviderProvisioning,
                                                                                  SamlUaaAuthenticationUserManager samlUaaAuthenticationUserManager,
                                                                                  ApplicationEventPublisher applicationEventPublisher,
                                                                                  UaaRelyingPartyRegistrationResolver relyingPartyRegistrationResolver) {

        return new Saml2BearerGrantAuthenticationConverter(relyingPartyRegistrationResolver, identityZoneManager,
                identityProviderProvisioning, samlUaaAuthenticationUserManager, applicationEventPublisher);
    }
}
