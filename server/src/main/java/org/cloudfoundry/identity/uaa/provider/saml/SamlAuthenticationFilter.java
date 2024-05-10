package org.cloudfoundry.identity.uaa.provider.saml;

import javax.servlet.Filter;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.web.Saml2WebSsoAuthenticationRequestFilter;

@Configuration
public class SamlAuthenticationFilter {

    @Autowired
    private RelyingPartyRegistrationRepository relyingPartyRegistrationRepository;

    @Bean
    Filter saml2WebSsoAuthenticationRequestFilter() {
        Saml2WebSsoAuthenticationRequestFilter saml2WebSsoAuthenticationRequestFilter = new Saml2WebSsoAuthenticationRequestFilter(relyingPartyRegistrationRepository);
        return saml2WebSsoAuthenticationRequestFilter;
    }

}
