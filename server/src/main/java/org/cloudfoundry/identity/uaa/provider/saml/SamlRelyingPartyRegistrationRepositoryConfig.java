package org.cloudfoundry.identity.uaa.provider.saml;

import lombok.extern.slf4j.Slf4j;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.saml.SamlKey;
import org.cloudfoundry.identity.uaa.util.KeyWithCert;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;

import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;

import static org.cloudfoundry.identity.uaa.provider.saml.SamlMetadataEndpoint.DEFAULT_REGISTRATION_ID;

@Configuration
@Slf4j
public class SamlRelyingPartyRegistrationRepositoryConfig {

    public static final String CLASSPATH_DUMMY_SAML_IDP_METADATA_XML = "classpath:dummy-saml-idp-metadata.xml";

    private final String samlEntityID;
    private final SamlConfigProps samlConfigProps;
    private final BootstrapSamlIdentityProviderData bootstrapSamlIdentityProviderData;
    private final String samlSpNameID;
    private final Boolean samlSignRequest;

    public SamlRelyingPartyRegistrationRepositoryConfig(@Qualifier("samlEntityID") String samlEntityID,
                                                        SamlConfigProps samlConfigProps,
                                                        BootstrapSamlIdentityProviderData bootstrapSamlIdentityProviderData,
                                                        @Value("${login.saml.nameID:urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified}")
                                                        String samlSpNameID,
                                                        @Value("${login.saml.signRequest:true}")
                                                        Boolean samlSignRequest
    ) {
        this.samlEntityID = samlEntityID;
        this.samlConfigProps = samlConfigProps;
        this.bootstrapSamlIdentityProviderData = bootstrapSamlIdentityProviderData;
        this.samlSpNameID = samlSpNameID;
        this.samlSignRequest = samlSignRequest;
    }

    @Autowired
    @Bean
    RelyingPartyRegistrationRepository relyingPartyRegistrationRepository(SamlIdentityProviderConfigurator samlIdentityProviderConfigurator) throws CertificateException {

        SamlKey activeSamlKey = samlConfigProps.getActiveSamlKey();
        KeyWithCert keyWithCert = new KeyWithCert(activeSamlKey.getKey(), activeSamlKey.getPassphrase(), activeSamlKey.getCertificate());

        List<RelyingPartyRegistration> relyingPartyRegistrations = new ArrayList<>();

        @SuppressWarnings("java:S125")
        // Spring Security requires at least one relyingPartyRegistration before SAML SP metadata generation;
        // and each relyingPartyRegistration needs to contain the SAML IDP metadata.
        // However, in the context of UAA external SAML IDP login, UAA does not know what the SAML IDP
        // metadata is until the operator configures the SAML IDP(s).
        // Also, some SAML IDPs might require you to supply the SAML SP metadata first before you can get the
        // SAML IDP metadata.
        // Hence, create a default relyingPartyRegistration with a hardcoded stub SAML IDP metadata
        // here to ensure that the SAML SP metadata will always be present,
        // even when there are no SAML IDPs configured.
        // See relevant issue: https://github.com/spring-projects/spring-security/issues/11369
        RelyingPartyRegistration defaultRelyingPartyRegistration = RelyingPartyRegistrationBuilder.buildRelyingPartyRegistration(
                samlEntityID, samlSpNameID, samlSignRequest, keyWithCert, CLASSPATH_DUMMY_SAML_IDP_METADATA_XML, DEFAULT_REGISTRATION_ID);
        relyingPartyRegistrations.add(defaultRelyingPartyRegistration);

        for (SamlIdentityProviderDefinition samlIdentityProviderDefinition : bootstrapSamlIdentityProviderData.getIdentityProviderDefinitions()) {
            relyingPartyRegistrations.add(
                    RelyingPartyRegistrationBuilder.buildRelyingPartyRegistration(
                            samlEntityID, samlSpNameID, samlSignRequest, keyWithCert,
                            samlIdentityProviderDefinition.getMetaDataLocation(),
                            samlIdentityProviderDefinition.getIdpEntityAlias())
            );
        }

        InMemoryRelyingPartyRegistrationRepository bootstrapRepo = new InMemoryRelyingPartyRegistrationRepository(relyingPartyRegistrations);
        ConfiguratorRelyingPartyRegistrationRepository configuratorRepo = new ConfiguratorRelyingPartyRegistrationRepository(samlSignRequest, samlEntityID, keyWithCert, samlIdentityProviderConfigurator);
        return new DelegatingRelyingPartyRegistrationRepository(bootstrapRepo, configuratorRepo);
    }

    @Autowired
    @Bean
    RelyingPartyRegistrationResolver relyingPartyRegistrationResolver(RelyingPartyRegistrationRepository relyingPartyRegistrationRepository) {
        return new DefaultRelyingPartyRegistrationResolver(relyingPartyRegistrationRepository);
    }
}
