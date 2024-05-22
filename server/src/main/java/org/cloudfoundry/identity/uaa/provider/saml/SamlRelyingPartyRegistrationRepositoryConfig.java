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
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrations;

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

    @Value("${login.saml.nameID:urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified}")
    private String samlSpNameID;

    @Value("${login.saml.signRequest:true}")
    private Boolean samlSignRequest;

    public SamlRelyingPartyRegistrationRepositoryConfig(@Qualifier("samlEntityID") String samlEntityID,
                                                        SamlConfigProps samlConfigProps,
                                                        BootstrapSamlIdentityProviderData bootstrapSamlIdentityProviderData
    ) {
        this.samlEntityID = samlEntityID;
        this.samlConfigProps = samlConfigProps;
        this.bootstrapSamlIdentityProviderData = bootstrapSamlIdentityProviderData;
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
        // metadata is, until the operator configures the SAML IDP(s). Also, some SAML
        // IDPs might require you to supply the SAML SP metadata first before you can obtain the
        // SAML IDP metadata. Hence, create a default relyingPartyRegistration with a hardcoded dummy SAML IDP metadata
        // here to ensure that the SAML SP metadata will always be present, even when there is no SAML IDPs configured.
        // See relevant issue: https://github.com/spring-projects/spring-security/issues/11369
        RelyingPartyRegistration defaultRelyingPartyRegistration = buildRelyingPartyRegistration(keyWithCert, CLASSPATH_DUMMY_SAML_IDP_METADATA_XML, DEFAULT_REGISTRATION_ID);
        relyingPartyRegistrations.add(defaultRelyingPartyRegistration);

        for (SamlIdentityProviderDefinition samlIdentityProviderDefinition : bootstrapSamlIdentityProviderData.getIdentityProviderDefinitions()) {
            relyingPartyRegistrations.add(
                    buildRelyingPartyRegistration(
                            keyWithCert,
                            samlIdentityProviderDefinition.getMetaDataLocation(),
                            samlIdentityProviderDefinition.getIdpEntityAlias())
            );
        }

        InMemoryRelyingPartyRegistrationRepository bootstrapRepo = new InMemoryRelyingPartyRegistrationRepository(relyingPartyRegistrations);
        ConfiguratorRelyingPartyRegistrationRepository configuratorRepo = new ConfiguratorRelyingPartyRegistrationRepository(samlSignRequest, samlEntityID, keyWithCert, samlIdentityProviderConfigurator);
        return new DelegatingRelyingPartyRegistrationRepository(bootstrapRepo, configuratorRepo);
    }

    private RelyingPartyRegistration buildRelyingPartyRegistration(KeyWithCert keyWithCert, String metadataLocation, String rpRegstrationId) {
        return RelyingPartyRegistrations
                .fromMetadataLocation(metadataLocation)
                .entityId(samlEntityID)
                .nameIdFormat(samlSpNameID)
                .registrationId(rpRegstrationId)
                // TODO: assertionConsumerServiceUrlTemplate can be configured here.
                .assertingPartyDetails(details -> details
                        .wantAuthnRequestsSigned(samlSignRequest)
                )
                .signingX509Credentials(cred -> cred
                        .add(Saml2X509Credential.signing(keyWithCert.getPrivateKey(), keyWithCert.getCertificate()))
                )
                .decryptionX509Credentials(cred -> cred
                        .add(Saml2X509Credential.decryption(keyWithCert.getPrivateKey(), keyWithCert.getCertificate()))
                )
                .build();
    }
}