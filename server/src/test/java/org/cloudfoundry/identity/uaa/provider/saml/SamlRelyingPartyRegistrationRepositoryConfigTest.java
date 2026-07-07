package org.cloudfoundry.identity.uaa.provider.saml;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.saml.SamlKey;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.saml2.provider.service.registration.AssertingPartyMetadata;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.web.client.ResourceAccessException;

import java.security.Security;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SamlRelyingPartyRegistrationRepositoryConfigTest {
    private static final String ENTITY_ID = "entityId";
    private static final String NAME_ID = "nameIdFormat";

    private static SamlConfigProps samlConfigProps;

    @Mock
    BootstrapSamlIdentityProviderData bootstrapSamlIdentityProviderData;

    @Mock
    SamlIdentityProviderConfigurator samlIdentityProviderConfigurator;

    @BeforeAll
    static void beforeAll() {
        Security.addProvider(new BouncyCastleFipsProvider());
        samlConfigProps = Saml2TestUtils.createTestSamlProperties();
        // DefaultRelyingPartyRegistrationRepository.findByRegistrationId() calls retrieveKeyManager(),
        // which reads this zone-scoped static state -- needed for any test that resolves a
        // registration id that falls through to the default/fallback repository.
        new IdentityZoneHolder.Initializer(null, new SamlKeyManagerFactory(samlConfigProps));
    }

    @Test
    void relyingPartyRegistrationRepository() {
        when(bootstrapSamlIdentityProviderData.getIdentityProviderDefinitions()).thenReturn(List.of(new SamlIdentityProviderDefinition()));
        SamlConfigProps localSamlConfigProps = new SamlConfigProps();
        localSamlConfigProps.setActiveKeyId(samlConfigProps.getActiveKeyId());
        localSamlConfigProps.setKeys(samlConfigProps.getKeys());
        Map<String, SamlKey> samlKeys = localSamlConfigProps.getKeys();
        localSamlConfigProps.setKeys(Map.of());
        localSamlConfigProps.setLegacyServiceProviderKey(samlKeys.entrySet().stream().findFirst().map(e -> e.getValue().getKey()).orElse(null));
        localSamlConfigProps.setLegacyServiceProviderCertificate(samlKeys.entrySet().stream().findFirst().map(e -> e.getValue().getCertificate()).orElse(null));
        SamlRelyingPartyRegistrationRepositoryConfig config = new SamlRelyingPartyRegistrationRepositoryConfig(ENTITY_ID,
                localSamlConfigProps, bootstrapSamlIdentityProviderData, NAME_ID, List.of());
        RelyingPartyRegistrationRepository repository = config.relyingPartyRegistrationRepository(samlIdentityProviderConfigurator);
        assertThat(repository).isNotNull();
    }

    @Test
    void relyingPartyRegistrationResolver() {
        SamlConfigProps localSamlConfigProps = new SamlConfigProps();
        localSamlConfigProps.setActiveKeyId(samlConfigProps.getActiveKeyId());
        localSamlConfigProps.setKeys(samlConfigProps.getKeys());
        Map<String, SamlKey> samlKeys = localSamlConfigProps.getKeys();
        localSamlConfigProps.setKeys(Map.of());
        localSamlConfigProps.setServiceProviderKey(samlKeys.entrySet().stream().findFirst().map(e -> e.getValue().getKey()).orElse(null));
        localSamlConfigProps.setServiceProviderCertificate(samlKeys.entrySet().stream().findFirst().map(e -> e.getValue().getCertificate()).orElse(null));
        SamlRelyingPartyRegistrationRepositoryConfig config = new SamlRelyingPartyRegistrationRepositoryConfig(ENTITY_ID,
                localSamlConfigProps, bootstrapSamlIdentityProviderData, NAME_ID, List.of());
        RelyingPartyRegistrationRepository repository = config.relyingPartyRegistrationRepository(samlIdentityProviderConfigurator);
        RelyingPartyRegistrationResolver resolver = config.relyingPartyRegistrationResolver(repository, ENTITY_ID, "http://localhost:8080/uaa");

        assertThat(resolver).isNotNull();
    }

    @Test
    void relyingPartyRegistrationRepositoryToleratesUnreachableBootstrapIdpMetadata() {
        SamlIdentityProviderDefinition unreachableIdp = new SamlIdentityProviderDefinition()
                .setMetaDataLocation("http://simplesamlphp.invalid/saml2/idp/metadata.php")
                .setIdpEntityAlias("unreachable-idp");
        when(bootstrapSamlIdentityProviderData.getIdentityProviderDefinitions()).thenReturn(List.of(unreachableIdp));
        when(samlIdentityProviderConfigurator.resolveMetadataXml(unreachableIdp))
                .thenThrow(new ResourceAccessException("I/O error on GET request for metadata URL"));

        SamlRelyingPartyRegistrationRepositoryConfig config = new SamlRelyingPartyRegistrationRepositoryConfig(ENTITY_ID,
                samlConfigProps, bootstrapSamlIdentityProviderData, NAME_ID, List.of());

        // A single unreachable bootstrap IDP must not prevent the bean (and therefore UAA startup)
        // from succeeding -- it should be logged and skipped, leaving the default registration intact.
        RelyingPartyRegistrationRepository repository = config.relyingPartyRegistrationRepository(samlIdentityProviderConfigurator);

        assertThat(repository).isNotNull();
        assertThat(repository.findByRegistrationId(SamlMetadataEndpoint.DEFAULT_REGISTRATION_ID)).isNotNull();

        // The unreachable IDP itself must not have been registered: DefaultRelyingPartyRegistrationRepository
        // is a catch-all fallback that returns a stub registration (entityId == the SP's own ENTITY_ID) for
        // *any* unknown id, so asserting that confirms "unreachable-idp" was skipped rather than partially
        // registered with broken/incomplete metadata.
        assertThat(repository.findByRegistrationId("unreachable-idp").getAssertingPartyMetadata().getEntityId())
                .isEqualTo(ENTITY_ID);
    }

    @Test
    void buildsRegistrationForExample() {
        SamlRelyingPartyRegistrationRepositoryConfig config = new SamlRelyingPartyRegistrationRepositoryConfig(ENTITY_ID,
                samlConfigProps, bootstrapSamlIdentityProviderData, NAME_ID, List.of());
        RelyingPartyRegistrationRepository repository = config.relyingPartyRegistrationRepository(samlIdentityProviderConfigurator);
        RelyingPartyRegistration registration = repository.findByRegistrationId(SamlMetadataEndpoint.DEFAULT_REGISTRATION_ID);
        assertThat(registration)
                .returns(SamlMetadataEndpoint.DEFAULT_REGISTRATION_ID, RelyingPartyRegistration::getRegistrationId)
                .returns(ENTITY_ID, RelyingPartyRegistration::getEntityId)
                .returns(NAME_ID, RelyingPartyRegistration::getNameIdFormat)
                // from functions
                .returns("{baseUrl}/saml/SSO/alias/entityId", RelyingPartyRegistration::getAssertionConsumerServiceLocation)
                .returns("{baseUrl}/saml/SingleLogout/alias/entityId", RelyingPartyRegistration::getSingleLogoutServiceResponseLocation)
                // from xml
                .extracting(RelyingPartyRegistration::getAssertingPartyMetadata)
                .returns("entityId", AssertingPartyMetadata::getEntityId);
    }
}
