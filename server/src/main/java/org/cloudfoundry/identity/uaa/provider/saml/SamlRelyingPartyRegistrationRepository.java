package org.cloudfoundry.identity.uaa.provider.saml;

import org.apache.commons.io.IOUtils;
import org.springframework.context.annotation.Bean;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrations;
import org.springframework.stereotype.Component;

import java.io.InputStream;
@Component
public class SamlRelyingPartyRegistrationRepository {

    // SAML SP metadata generation relies on a relyingPartyRegistration, which requires a valid SAML IDP
    // metadata. In the context of UAA external SAML IDP login, UAA does not know what the SAML IDP
    // metadata is, until the operator adds it via the /identity-providers endpoint. Also, some SAML
    // IDPs might require you to supply the SAML SP metadata first before you can obtain the
    // SAML IDP metadata. Hence, supply a hardcoded dummy SAML IDP metadata here to unblock the SAML
    // SP metadata generation. See relevant issue: https://github.com/spring-projects/spring-security/issues/11369
    public static final String CLASSPATH_DUMMY_SAML_IDP_METADATA_XML = "classpath:dummy-saml-idp-metadata.xml";

    @Bean
    RelyingPartyRegistrationRepository relyingPartyRegistrationRepository() {
        RelyingPartyRegistration relyingPartyRegistration = RelyingPartyRegistrations
                .fromMetadataLocation(CLASSPATH_DUMMY_SAML_IDP_METADATA_XML)
                .registrationId("example")
                .build();
        return new InMemoryRelyingPartyRegistrationRepository(relyingPartyRegistration);
    }

}
