package org.cloudfoundry.identity.uaa.provider.saml;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.saml2.provider.service.metadata.OpenSamlMetadataResolver;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.Saml2MetadataFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
public class SamlConfiguration {
    public static final String AGGREGATE_SPRING_SECURITY_FILTER_CHAIN_ID = "aggregateSpringSecurityFilterChain";

    @Bean(name = AGGREGATE_SPRING_SECURITY_FILTER_CHAIN_ID)
    @Lazy
    Saml2MetadataFilter aggregateSpringSecurityFilterChain(
            @Autowired RelyingPartyRegistrationRepository relyingPartyRegistrationRepository) {

        Converter<HttpServletRequest, RelyingPartyRegistration> relyingPartyRegistrationResolver =
                new DefaultRelyingPartyRegistrationResolver(relyingPartyRegistrationRepository);
        Saml2MetadataFilter filter = new Saml2MetadataFilter(
                relyingPartyRegistrationResolver,
                new OpenSamlMetadataResolver());
        filter.setRequestMatcher(new AntPathRequestMatcher("/saml/metadata/**/{registrationId}", "GET"));

        return filter;
    }

}