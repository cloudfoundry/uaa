package org.cloudfoundry.identity.uaa.provider.saml;

import lombok.extern.slf4j.Slf4j;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
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

    public SamlRelyingPartyRegistrationRepositoryConfig(@Qualifier("samlEntityID") String samlEntityID,
                                                        SamlConfigProps samlConfigProps,
                                                        BootstrapSamlIdentityProviderData bootstrapSamlIdentityProviderData,
                                                        @Value("${login.saml.nameID:urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified}")
                                                        String samlSpNameID
    ) {
        this.samlEntityID = samlEntityID;
        this.samlConfigProps = samlConfigProps;
        this.bootstrapSamlIdentityProviderData = bootstrapSamlIdentityProviderData;
        this.samlSpNameID = samlSpNameID;
    }

    @Autowired
    @Bean
    RelyingPartyRegistrationRepository relyingPartyRegistrationRepository(SamlIdentityProviderConfigurator samlIdentityProviderConfigurator) {
        SamlKeyManagerFactory.SamlConfigPropsSamlKeyManagerImpl samlKeyManager = new SamlKeyManagerFactory.SamlConfigPropsSamlKeyManagerImpl(samlConfigProps);
        List<KeyWithCert> defaultKeysWithCerts =samlKeyManager.getAvailableCredentials();

        List<RelyingPartyRegistration> relyingPartyRegistrations = new ArrayList<>();
        String uaaWideSamlEntityIDAlias = samlConfigProps.getEntityIDAlias() != null ? samlConfigProps.getEntityIDAlias() : samlEntityID;

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
        RelyingPartyRegistration exampleRelyingPartyRegistration = RelyingPartyRegistrationBuilder.buildRelyingPartyRegistration(
                samlEntityID, samlSpNameID, defaultKeysWithCerts, CLASSPATH_DUMMY_SAML_IDP_METADATA_XML, DEFAULT_REGISTRATION_ID, uaaWideSamlEntityIDAlias, samlConfigProps.getSignRequest());
        relyingPartyRegistrations.add(exampleRelyingPartyRegistration);

        for (SamlIdentityProviderDefinition samlIdentityProviderDefinition : bootstrapSamlIdentityProviderData.getIdentityProviderDefinitions()) {
            relyingPartyRegistrations.add(
                    RelyingPartyRegistrationBuilder.buildRelyingPartyRegistration(
                            samlEntityID, samlSpNameID, defaultKeysWithCerts,
                            samlIdentityProviderDefinition.getMetaDataLocation(),
                            samlIdentityProviderDefinition.getIdpEntityAlias(),
                            uaaWideSamlEntityIDAlias,
                            samlConfigProps.getSignRequest())
            );
        }

        InMemoryRelyingPartyRegistrationRepository bootstrapRepo = new InMemoryRelyingPartyRegistrationRepository(relyingPartyRegistrations);
        ConfiguratorRelyingPartyRegistrationRepository configuratorRepo = new ConfiguratorRelyingPartyRegistrationRepository(samlEntityID, uaaWideSamlEntityIDAlias, samlIdentityProviderConfigurator);
        DefaultRelyingPartyRegistrationRepository defaultRepo = new DefaultRelyingPartyRegistrationRepository(samlEntityID, uaaWideSamlEntityIDAlias);
        return new DelegatingRelyingPartyRegistrationRepository(bootstrapRepo, configuratorRepo, defaultRepo);
    }

    @Autowired
    @Bean
    RelyingPartyRegistrationResolver relyingPartyRegistrationResolver(RelyingPartyRegistrationRepository relyingPartyRegistrationRepository) {
        return new DefaultRelyingPartyRegistrationResolver(relyingPartyRegistrationRepository);
    }
}
