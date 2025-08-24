package org.cloudfoundry.identity.uaa.provider.saml;

import lombok.extern.slf4j.Slf4j;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.util.KeyWithCert;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.cloudfoundry.identity.uaa.provider.saml.SamlMetadataEndpoint.DEFAULT_REGISTRATION_ID;

@Configuration
@Slf4j
public class SamlRelyingPartyRegistrationRepositoryConfig {

    private final String samlEntityID;
    private final SamlConfigProps samlConfigProps;
    private final BootstrapSamlIdentityProviderData bootstrapSamlIdentityProviderData;
    private final String samlSpNameID;
    private final List<SignatureAlgorithm> signatureAlgorithms;

    public SamlRelyingPartyRegistrationRepositoryConfig(@Qualifier("samlEntityID") String samlEntityID,
            SamlConfigProps samlConfigProps,
            BootstrapSamlIdentityProviderData bootstrapSamlIdentityProviderData,
            @Value("${login.saml.nameID:urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified}")
            String samlSpNameID, List<SignatureAlgorithm> signatureAlgorithms
    ) {
        this.samlEntityID = samlEntityID;
        this.samlConfigProps = samlConfigProps;
        this.bootstrapSamlIdentityProviderData = bootstrapSamlIdentityProviderData;
        this.samlSpNameID = samlSpNameID;
        this.signatureAlgorithms = signatureAlgorithms;
    }

    @DependsOn({"setUpBouncyCastle"})
    @Bean
    RelyingPartyRegistrationRepository relyingPartyRegistrationRepository(SamlIdentityProviderConfigurator samlIdentityProviderConfigurator) {
        SamlKeyManagerFactory.SamlConfigPropsSamlKeyManagerImpl samlKeyManager = new SamlKeyManagerFactory.SamlConfigPropsSamlKeyManagerImpl(samlConfigProps);
        List<KeyWithCert> defaultKeysWithCerts = samlKeyManager.getAvailableCredentials();

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
        RelyingPartyRegistrationBuilder.Params exampleParams = RelyingPartyRegistrationBuilder.Params.builder()
                .samlEntityID(samlEntityID)
                .samlSpNameId(samlSpNameID)
                .keys(defaultKeysWithCerts)
                .metadataLocation(RelyingPartyRegistrationBuilder.createOwnMetadata(samlEntityID, defaultKeysWithCerts))
                .rpRegistrationId(DEFAULT_REGISTRATION_ID)
                .samlSpAlias(uaaWideSamlEntityIDAlias)
                .requestSigned(samlConfigProps.getSignRequest())
                .signatureAlgorithms(signatureAlgorithms)
                .build();
        RelyingPartyRegistration exampleRelyingPartyRegistration = RelyingPartyRegistrationBuilder.buildRelyingPartyRegistration(exampleParams);
        relyingPartyRegistrations.add(exampleRelyingPartyRegistration);

        for (SamlIdentityProviderDefinition samlIdentityProviderDefinition : bootstrapSamlIdentityProviderData.getIdentityProviderDefinitions()) {
            RelyingPartyRegistrationBuilder.Params params = RelyingPartyRegistrationBuilder.Params.builder()
                    .samlEntityID(samlEntityID)
                    .samlSpNameId(samlSpNameID)
                    .keys(defaultKeysWithCerts)
                    .metadataLocation(samlIdentityProviderDefinition.getMetaDataLocation())
                    .rpRegistrationId(samlIdentityProviderDefinition.getIdpEntityAlias())
                    .samlSpAlias(uaaWideSamlEntityIDAlias)
                    .requestSigned(samlConfigProps.getSignRequest())
                    .signatureAlgorithms(signatureAlgorithms)
                    .build();
            try {
                relyingPartyRegistrations.add(RelyingPartyRegistrationBuilder.buildRelyingPartyRegistration(params));
            } catch (Saml2Exception e) {
                log.error("Error building relying party", e);
            }
        }

        InMemoryRelyingPartyRegistrationRepository bootstrapRepo = new InMemoryRelyingPartyRegistrationRepository(relyingPartyRegistrations);
        ConfiguratorRelyingPartyRegistrationRepository configuratorRepo =
                new ConfiguratorRelyingPartyRegistrationRepository(samlEntityID, uaaWideSamlEntityIDAlias,
                        samlIdentityProviderConfigurator, signatureAlgorithms, samlSpNameID);
        DefaultRelyingPartyRegistrationRepository defaultRepo =
                new DefaultRelyingPartyRegistrationRepository(samlEntityID, uaaWideSamlEntityIDAlias, signatureAlgorithms, samlSpNameID);

        return new DelegatingRelyingPartyRegistrationRepository(bootstrapRepo, configuratorRepo, defaultRepo);
    }

    @Bean
    UaaRelyingPartyRegistrationResolver relyingPartyRegistrationResolver(RelyingPartyRegistrationRepository relyingPartyRegistrationRepository,
            @Qualifier("samlEntityID") String samlEntityID) {
        return new UaaRelyingPartyRegistrationResolver(relyingPartyRegistrationRepository, Optional.ofNullable(samlConfigProps.getEntityIDAlias()).orElse(samlEntityID));
    }
}
