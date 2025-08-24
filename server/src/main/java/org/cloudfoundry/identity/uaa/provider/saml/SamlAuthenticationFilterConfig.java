package org.cloudfoundry.identity.uaa.provider.saml;

import org.cloudfoundry.identity.uaa.authentication.SamlLogoutRequestValidator;
import org.cloudfoundry.identity.uaa.authentication.SamlLogoutResponseValidator;
import org.cloudfoundry.identity.uaa.login.UaaAuthenticationFailureHandler;
import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.security.web.CookieBasedCsrfTokenRepository;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.web.UaaSavedRequestAwareAuthenticationSuccessHandler;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
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
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.csrf.CsrfLogoutHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import jakarta.servlet.Filter;

/**
 * Configuration for SAML Filters and Authentication Providers for SAML Authentication.
 */
@Configuration
public class SamlAuthenticationFilterConfig {

    public static final String BACKWARD_COMPATIBLE_ASSERTION_CONSUMER_FILTER_PROCESSES_URI = "/saml/SSO/alias/{registrationId}";

    /**
     * Handles building and forwarding the SAML2 Authentication Request to the IDP.
     */
    @Bean
    FilterRegistrationBean<Filter> saml2WebSsoAuthenticationRequestFilter(RelyingPartyRegistrationResolver relyingPartyRegistrationResolver) {
        OpenSaml4AuthenticationRequestResolver openSaml4AuthenticationRequestResolver = new OpenSaml4AuthenticationRequestResolver(relyingPartyRegistrationResolver);

        Saml2WebSsoAuthenticationRequestFilter filter = new Saml2WebSsoAuthenticationRequestFilter(openSaml4AuthenticationRequestResolver);
        FilterRegistrationBean<Filter> bean = new FilterRegistrationBean<>(filter);
        bean.setEnabled(false);
        return bean;
    }

    @Bean
    SecurityContextRepository securityContextRepository() {
        return new HttpSessionSecurityContextRepository();
    }

    @Bean
    SamlUaaAuthenticationUserManager samlUaaAuthenticationUserManager(IdentityZoneManager identityZoneManager,
            final JdbcIdentityProviderProvisioning identityProviderProvisioning,
            ScimGroupExternalMembershipManager externalMembershipManager,
            final UaaUserDatabase userDatabase,
            ApplicationEventPublisher applicationEventPublisher) {

        SamlUaaAuthenticationAttributesConverter attributesConverter = new SamlUaaAuthenticationAttributesConverter();
        SamlUaaAuthenticationAuthoritiesConverter authoritiesConverter = new SamlUaaAuthenticationAuthoritiesConverter(externalMembershipManager);
        SamlUaaAuthenticationUserManager samlUaaAuthenticationUserManager =
                new SamlUaaAuthenticationUserManager(identityZoneManager, identityProviderProvisioning, userDatabase,
                        attributesConverter, authoritiesConverter);
        samlUaaAuthenticationUserManager.setApplicationEventPublisher(applicationEventPublisher);

        return samlUaaAuthenticationUserManager;
    }

    @Bean
    AuthenticationProvider samlAuthenticationProvider(IdentityZoneManager identityZoneManager,
            SamlUaaAuthenticationUserManager samlUaaAuthenticationUserManager,
            ApplicationEventPublisher applicationEventPublisher,
            SamlConfigProps samlConfigProps) {

        SamlUaaResponseAuthenticationConverter samlResponseAuthenticationConverter =
                new SamlUaaResponseAuthenticationConverter(identityZoneManager, samlUaaAuthenticationUserManager);
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
    @Bean
    FilterRegistrationBean<Filter> saml2WebSsoAuthenticationFilter(AuthenticationProvider samlAuthenticationProvider,
            UaaRelyingPartyRegistrationResolver relyingPartyRegistrationResolver,
            SecurityContextRepository securityContextRepository,
            SamlLoginAuthenticationFailureHandler samlLoginAuthenticationFailureHandler,
            UaaSavedRequestAwareAuthenticationSuccessHandler samlLoginAuthenticationSuccessHandler) {

        Saml2AuthenticationTokenConverter saml2AuthenticationTokenConverter = new Saml2AuthenticationTokenConverter((RelyingPartyRegistrationResolver) relyingPartyRegistrationResolver);
        Saml2WebSsoAuthenticationFilter filter = new Saml2WebSsoAuthenticationFilter(saml2AuthenticationTokenConverter, BACKWARD_COMPATIBLE_ASSERTION_CONSUMER_FILTER_PROCESSES_URI);

        ProviderManager authenticationManager = new ProviderManager(samlAuthenticationProvider);
        filter.setAuthenticationManager(authenticationManager);
        filter.setSecurityContextRepository(securityContextRepository);
        filter.setFilterProcessesUrl(BACKWARD_COMPATIBLE_ASSERTION_CONSUMER_FILTER_PROCESSES_URI);
        filter.setAuthenticationFailureHandler(samlLoginAuthenticationFailureHandler);
        filter.setAuthenticationSuccessHandler(samlLoginAuthenticationSuccessHandler);

        FilterRegistrationBean<Filter> bean = new FilterRegistrationBean<>(filter);
        bean.setEnabled(false);
        return bean;
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

    @Bean
    Saml2LogoutRequestResolver saml2LogoutRequestResolver(RelyingPartyRegistrationResolver relyingPartyRegistrationResolver) {
        return new OpenSaml4LogoutRequestResolver(relyingPartyRegistrationResolver);
    }

    /**
     * Handles a Relying Party Initiated Logout
     * and forwards a Saml2LogoutRequest to IDP/asserting party if configured.
     */
    @Bean
    Saml2RelyingPartyInitiatedLogoutSuccessHandler saml2RelyingPartyInitiatedLogoutSuccessHandler(Saml2LogoutRequestResolver logoutRequestResolver) {
        return new Saml2RelyingPartyInitiatedLogoutSuccessHandler(logoutRequestResolver);
    }

    /**
     * Handles a return SAML2LogoutResponse from IDP/asserting party in response to a Saml2LogoutRequest from UAA.
     */
    @Bean
    FilterRegistrationBean<Saml2LogoutResponseFilter> saml2LogoutResponseFilter(RelyingPartyRegistrationResolver relyingPartyRegistrationResolver,
            UaaDelegatingLogoutSuccessHandler successHandler) {

        // This validator ignores missing signatures in the SAML2 Logout Response
        Saml2LogoutResponseValidator openSamlLogoutResponseValidator = new SamlLogoutResponseValidator();

        Saml2LogoutResponseFilter filter = new Saml2LogoutResponseFilter(relyingPartyRegistrationResolver, openSamlLogoutResponseValidator, successHandler);
        filter.setLogoutRequestMatcher(new AntPathRequestMatcher("/saml/SingleLogout/alias/{registrationId}"));

        FilterRegistrationBean<Saml2LogoutResponseFilter> bean = new FilterRegistrationBean<>(filter);
        bean.setEnabled(false);
        return bean;
    }

    /**
     * Handles an incoming Saml2LogoutRequest from an Asserting Party Initiated Logout
     */
    @Bean
    FilterRegistrationBean<Saml2LogoutRequestFilter> saml2LogoutRequestFilter(UaaRelyingPartyRegistrationResolver relyingPartyRegistrationResolver,
            UaaAuthenticationFailureHandler authenticationFailureHandler,
            CookieBasedCsrfTokenRepository loginCookieCsrfRepository) {

        // This validator ignores missing signatures in the SAML2 Logout Response
        Saml2LogoutRequestValidator logoutRequestValidator = new SamlLogoutRequestValidator();
        Saml2LogoutResponseResolver logoutResponseResolver = new OpenSaml4LogoutResponseResolver(relyingPartyRegistrationResolver);

        SecurityContextLogoutHandler securityContextLogoutHandlerWithHandler = new SecurityContextLogoutHandler();
        CsrfLogoutHandler csrfLogoutHandler = new CsrfLogoutHandler(loginCookieCsrfRepository);
        CookieClearingLogoutHandler cookieClearingLogoutHandlerWithHandler = new CookieClearingLogoutHandler("JSESSIONID");

        Saml2LogoutRequestFilter filter = new Saml2LogoutRequestFilter(relyingPartyRegistrationResolver,
                logoutRequestValidator, logoutResponseResolver,
                authenticationFailureHandler, securityContextLogoutHandlerWithHandler, csrfLogoutHandler,
                cookieClearingLogoutHandlerWithHandler);
        filter.setLogoutRequestMatcher(new AntPathRequestMatcher("/saml/SingleLogout/alias/*"));
        FilterRegistrationBean<Saml2LogoutRequestFilter> bean = new FilterRegistrationBean<>(filter);
        bean.setEnabled(false);
        return bean;
    }

    /**
     * Handles Authentication for the Saml2 Bearer Grant.
     */
    @Bean
    Saml2BearerGrantAuthenticationConverter samlBearerGrantAuthenticationProvider(IdentityZoneManager identityZoneManager,
            SamlUaaAuthenticationUserManager samlUaaAuthenticationUserManager,
            UaaRelyingPartyRegistrationResolver relyingPartyRegistrationResolver) {

        return new Saml2BearerGrantAuthenticationConverter(relyingPartyRegistrationResolver, identityZoneManager,
                samlUaaAuthenticationUserManager);
    }
}
