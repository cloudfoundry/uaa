package org.cloudfoundry.identity.uaa.provider.saml;

import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.Saml2WebSsoAuthenticationRequestFilter;
import org.springframework.security.saml2.provider.service.web.authentication.OpenSaml4AuthenticationRequestResolver;
import org.springframework.security.saml2.provider.service.web.authentication.Saml2WebSsoAuthenticationFilter;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.Filter;
import javax.servlet.http.HttpServletRequest;

/**
 * Configuration for SAML Filters and Authentication Providers for SAML Authentication.
 */
@Configuration
public class SamlAuthenticationFilterConfig {

    /**
     * Handles building and forwarding the SAML2 Authentication Request to the IDP.
     */
    @Autowired
    @Bean
    Filter saml2WebSsoAuthenticationRequestFilter(RelyingPartyRegistrationRepository relyingPartyRegistrationRepository) {
        SamlRelayStateResolver relayStateResolver = new SamlRelayStateResolver();

        DefaultRelyingPartyRegistrationResolver defaultRelyingPartyRegistrationResolver = new DefaultRelyingPartyRegistrationResolver(relyingPartyRegistrationRepository);
        OpenSaml4AuthenticationRequestResolver openSaml4AuthenticationRequestResolver = new OpenSaml4AuthenticationRequestResolver(defaultRelyingPartyRegistrationResolver);
        openSaml4AuthenticationRequestResolver.setRelayStateResolver(relayStateResolver);

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
                                                      ApplicationEventPublisher applicationEventPublisher) {

        SamlUaaAuthenticationAttributesConverter attributesConverter = new SamlUaaAuthenticationAttributesConverter();
        SamlUaaAuthenticationAuthoritiesConverter authoritiesConverter = new SamlUaaAuthenticationAuthoritiesConverter(externalMembershipManager);

        SamlUaaResponseAuthenticationConverter samlResponseAuthenticationConverter =
                new SamlUaaResponseAuthenticationConverter(identityZoneManager, identityProviderProvisioning,
                        samlUaaAuthenticationUserManager, attributesConverter, authoritiesConverter);
        samlResponseAuthenticationConverter.setApplicationEventPublisher(applicationEventPublisher);

        OpenSaml4AuthenticationProvider samlResponseAuthenticationProvider = new OpenSaml4AuthenticationProvider();
        samlResponseAuthenticationProvider.setResponseAuthenticationConverter(samlResponseAuthenticationConverter);

        return samlResponseAuthenticationProvider;
    }

    /**
     * Handles the SAML2 Authentication Response and creates an Authentication object.
     */
    @Autowired
    @Bean
    Filter saml2WebSsoAuthenticationFilter(AuthenticationProvider samlAuthenticationProvider,
                                           RelyingPartyRegistrationRepository relyingPartyRegistrationRepository,
                                           SecurityContextRepository securityContextRepository) {

        Saml2WebSsoAuthenticationFilter saml2WebSsoAuthenticationFilter = new Saml2WebSsoAuthenticationFilter(relyingPartyRegistrationRepository);

        ProviderManager authenticationManager = new ProviderManager(samlAuthenticationProvider);
        saml2WebSsoAuthenticationFilter.setAuthenticationManager(authenticationManager);
        saml2WebSsoAuthenticationFilter.setSecurityContextRepository(securityContextRepository);

        return saml2WebSsoAuthenticationFilter;
    }
}

class SamlRelayStateResolver implements Converter<HttpServletRequest, String> {
    RequestMatcher requestMatcher = new AntPathRequestMatcher("/saml2/authenticate/{registrationId}");

    @Override
    public String convert(HttpServletRequest request) {
        RequestMatcher.MatchResult result = this.requestMatcher.matcher(request);
        if (!result.isMatch()) {
            return null;
        }

        return result.getVariables().get("registrationId");
    }
}
