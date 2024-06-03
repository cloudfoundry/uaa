package org.cloudfoundry.identity.uaa.provider.saml;

import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.springframework.beans.factory.annotation.Autowired;
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
    AuthenticationProvider samlAuthenticationProvider(IdentityZoneManager identityZoneManager,
                                                      final UaaUserDatabase userDatabase,
                                                      final JdbcIdentityProviderProvisioning identityProviderProvisioning) {

//        SamlUaaResponseAuthenticationConverter samlResponseAuthenticationConverter =
//                new SamlUaaResponseAuthenticationConverter(identityZoneManager, userDatabase, identityProviderProvisioning);
//
//        OpenSaml4AuthenticationProvider authProvider = new OpenSaml4AuthenticationProvider();
//        //authProvider.setAssertionValidator(OpenSaml40CompatibleAssertionValidators.createDefaultAssertionValidator());
//        authProvider.setResponseAuthenticationConverter(samlResponseAuthenticationConverter);

        return new SamlLoginAuthenticationProvider(identityZoneManager, userDatabase, identityProviderProvisioning);
    }

    @Autowired
    @Bean
    Filter saml2WebSsoAuthenticationFilter(AuthenticationProvider samlAuthenticationProvider,
                                           RelyingPartyRegistrationRepository relyingPartyRegistrationRepository,
                                           SecurityContextRepository securityContextRepository) {

        Saml2WebSsoAuthenticationFilter saml2WebSsoAuthenticationFilter = new Saml2WebSsoAuthenticationFilter(relyingPartyRegistrationRepository);

        ProviderManager authenticationManager = new ProviderManager(samlAuthenticationProvider);
        // TODO: set the publisher authenticationManager setAuthenticationEventPublisher(authenticationEventPublisher)

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
