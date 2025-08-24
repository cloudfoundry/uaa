package org.cloudfoundry.identity.uaa.provider.saml;

import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.SamlConfig;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.util.FileCopyUtils;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.UncheckedIOException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.cloudfoundry.identity.uaa.provider.saml.TestCredentialObjects.keyName1;
import static org.cloudfoundry.identity.uaa.provider.saml.TestCredentialObjects.keyName2;
import static org.cloudfoundry.identity.uaa.provider.saml.TestCredentialObjects.samlKey1;
import static org.cloudfoundry.identity.uaa.provider.saml.TestCredentialObjects.samlKey2;
import static org.cloudfoundry.identity.uaa.provider.saml.TestCredentialObjects.x509Certificate1;
import static org.cloudfoundry.identity.uaa.provider.saml.TestCredentialObjects.x509Certificate2;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;
import static org.opensaml.xmlsec.signature.support.SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256;
import static org.opensaml.xmlsec.signature.support.SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA512;

@ExtendWith(MockitoExtension.class)
class ConfiguratorRelyingPartyRegistrationRepositoryTest {
    private static final String ENTITY_ID = "entityId";
    private static final String ENTITY_ID_ALIAS = "entityIdAlias";
    private static final String REGISTRATION_ID = "registrationId";
    private static final String REGISTRATION_ID_2 = "registrationId2";
    private static final String DEFAULT_NAME_ID = "defaultNameId";
    private static final String NAME_ID = "name1";
    private static final String ZONE_DOMAIN = "zoneDomain";
    private static final String ZONED_ENTITY_ID = "zoneDomain.entityId";
    private static final String ZONE_SPECIFIC_ENTITY_ID = "zoneEntityId";

    private static final SamlConfigProps samlConfigProps = new SamlConfigProps();

    @Mock
    private SamlIdentityProviderConfigurator configurator;

    @Mock
    private IdentityZone identityZone;

    @Mock
    private SamlIdentityProviderDefinition definition;

    @Mock
    private IdentityZoneConfiguration identityZoneConfiguration;

    @Mock
    private SamlConfig samlConfig;

    private ConfiguratorRelyingPartyRegistrationRepository repository;

    @BeforeAll
    static void beforeAll() {
        new IdentityZoneHolder.Initializer(null, new SamlKeyManagerFactory(samlConfigProps));
    }

    @BeforeEach
    void beforeEach() {
        repository = spy(new ConfiguratorRelyingPartyRegistrationRepository(ENTITY_ID, ENTITY_ID_ALIAS, configurator, List.of(), DEFAULT_NAME_ID));
    }

    @Test
    void constructorWithNullConfiguratorThrows() {
        List<SignatureAlgorithm> signatureAlgorithms = List.of();
        assertThatThrownBy(() -> new ConfiguratorRelyingPartyRegistrationRepository(
                ENTITY_ID, ENTITY_ID_ALIAS, null, signatureAlgorithms, DEFAULT_NAME_ID)
        ).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void findByRegistrationIdWithMultipleInDb() {
        when(repository.retrieveZone()).thenReturn(identityZone);
        when(identityZone.isUaa()).thenReturn(true);
        when(identityZone.getConfig()).thenReturn(identityZoneConfiguration);
        when(identityZoneConfiguration.getSamlConfig()).thenReturn(samlConfig);

        //definition 1
        when(definition.getIdpEntityAlias()).thenReturn(REGISTRATION_ID);
        when(definition.getNameID()).thenReturn(NAME_ID);
        when(definition.getMetaDataLocation()).thenReturn("saml-sample-metadata.xml");

        //other definitions
        SamlIdentityProviderDefinition otherDefinition = mock(SamlIdentityProviderDefinition.class);
        when(otherDefinition.getIdpEntityAlias()).thenReturn("otherRegistrationId");
        SamlIdentityProviderDefinition anotherDefinition = mock(SamlIdentityProviderDefinition.class);

        when(configurator.getIdentityProviderDefinitionsForZone(identityZone)).thenReturn(Arrays.asList(otherDefinition, definition, anotherDefinition));
        RelyingPartyRegistration registration = repository.findByRegistrationId(REGISTRATION_ID);
        assertThat(registration)
                // from definition
                .returns(REGISTRATION_ID, RelyingPartyRegistration::getRegistrationId)
                .returns(ENTITY_ID, RelyingPartyRegistration::getEntityId)
                .returns(NAME_ID, RelyingPartyRegistration::getNameIdFormat)
                // from functions
                .returns("{baseUrl}/saml/SSO/alias/entityIdAlias", RelyingPartyRegistration::getAssertionConsumerServiceLocation)
                .returns("{baseUrl}/saml/SingleLogout/alias/entityIdAlias", RelyingPartyRegistration::getSingleLogoutServiceResponseLocation)
                // from xml
                .extracting(RelyingPartyRegistration::getAssertingPartyDetails)
                .returns("https://idp-saml.ua3.int/simplesaml/saml2/idp/metadata.php", RelyingPartyRegistration.AssertingPartyDetails::getEntityId);
    }

    @Test
    void findByRegistrationIdWhenNoneFound() {
        when(repository.retrieveZone()).thenReturn(identityZone);
        assertThat(repository.findByRegistrationId("registrationIdNotFound")).isNull();
    }

    @Test
    void getsDefaultOnNoExactMatch() {
        String metadata = loadResouceAsString("saml-sample-metadata.xml");
        when(repository.retrieveZone()).thenReturn(identityZone);
        when(identityZone.isUaa()).thenReturn(true);
        when(identityZone.getConfig()).thenReturn(identityZoneConfiguration);
        when(identityZoneConfiguration.getSamlConfig()).thenReturn(samlConfig);
        when(definition.getIdpEntityAlias()).thenReturn(REGISTRATION_ID);
        when(definition.getNameID()).thenReturn(NAME_ID);
        when(definition.getMetaDataLocation()).thenReturn(metadata);
        when(configurator.getIdentityProviderDefinitionsForOrigin(identityZone, "defaultRegistrationId")).thenReturn(definition);

        assertThat(repository.findByRegistrationId("defaultRegistrationId"))
                .returns(REGISTRATION_ID, RelyingPartyRegistration::getRegistrationId);
    }

    @Test
    void buildsCorrectRegistrationWhenMetadataXmlIsStored() {
        String metadata = loadResouceAsString("saml-sample-metadata.xml");
        when(repository.retrieveZone()).thenReturn(identityZone);
        when(identityZone.isUaa()).thenReturn(true);
        when(identityZone.getConfig()).thenReturn(identityZoneConfiguration);
        when(identityZoneConfiguration.getSamlConfig()).thenReturn(samlConfig);
        when(definition.getIdpEntityAlias()).thenReturn(REGISTRATION_ID);
        when(definition.getNameID()).thenReturn(NAME_ID);
        when(definition.getMetaDataLocation()).thenReturn(metadata);
        when(configurator.getIdentityProviderDefinitionsForZone(identityZone)).thenReturn(List.of(definition));

        RelyingPartyRegistration registration = repository.findByRegistrationId(REGISTRATION_ID);
        assertThat(registration)
                // from definition
                .returns(REGISTRATION_ID, RelyingPartyRegistration::getRegistrationId)
                .returns(ENTITY_ID, RelyingPartyRegistration::getEntityId)
                .returns(NAME_ID, RelyingPartyRegistration::getNameIdFormat)
                // from functions
                .returns("{baseUrl}/saml/SSO/alias/entityIdAlias", RelyingPartyRegistration::getAssertionConsumerServiceLocation)
                .returns("{baseUrl}/saml/SingleLogout/alias/entityIdAlias", RelyingPartyRegistration::getSingleLogoutServiceResponseLocation)
                // from xml
                .extracting(RelyingPartyRegistration::getAssertingPartyDetails)
                .returns("https://idp-saml.ua3.int/simplesaml/saml2/idp/metadata.php", RelyingPartyRegistration.AssertingPartyDetails::getEntityId);
    }

    @Test
    void zoneWithCredentialsUsesCorrectValues() {
        samlConfigProps.setKeys(Map.of(keyName1(), samlKey1(), keyName2(), samlKey2()));
        samlConfigProps.setActiveKeyId(keyName1());

        when(repository.retrieveZone()).thenReturn(identityZone);
        when(identityZone.getConfig()).thenReturn(identityZoneConfiguration);
        when(identityZoneConfiguration.getSamlConfig()).thenReturn(samlConfig);
        when(definition.getIdpEntityAlias()).thenReturn(REGISTRATION_ID);
        when(definition.getMetaDataLocation()).thenReturn("saml-sample-metadata.xml");
        when(configurator.getIdentityProviderDefinitionsForZone(identityZone)).thenReturn(List.of(definition));

        RelyingPartyRegistration registration = repository.findByRegistrationId(REGISTRATION_ID);
        assertThat(registration.getDecryptionX509Credentials())
                .hasSize(1)
                .first()
                .extracting(Saml2X509Credential::getCertificate)
                .isEqualTo(x509Certificate1());
        assertThat(registration.getSigningX509Credentials())
                .hasSize(2)
                .first()
                .extracting(Saml2X509Credential::getCertificate)
                .isEqualTo(x509Certificate1());
        // Check the second element
        assertThat(registration.getSigningX509Credentials())
                .element(1)
                .extracting(Saml2X509Credential::getCertificate)
                .isEqualTo(x509Certificate2());
    }

    @Test
    void buildsCorrectRegistrationWhenMetadataLocationIsStored() {
        when(repository.retrieveZone()).thenReturn(identityZone);
        when(identityZone.isUaa()).thenReturn(true);
        when(identityZone.getConfig()).thenReturn(identityZoneConfiguration);
        when(identityZoneConfiguration.getSamlConfig()).thenReturn(samlConfig);
        when(definition.getIdpEntityAlias()).thenReturn(REGISTRATION_ID_2);
        when(definition.getNameID()).thenReturn(NAME_ID);
        when(definition.getMetaDataLocation()).thenReturn("saml-sample-metadata.xml");
        when(configurator.getIdentityProviderDefinitionsForZone(identityZone)).thenReturn(List.of(definition));

        RelyingPartyRegistration registration = repository.findByRegistrationId(REGISTRATION_ID_2);
        assertThat(registration)
                // from definition
                .returns(REGISTRATION_ID_2, RelyingPartyRegistration::getRegistrationId)
                .returns(ENTITY_ID, RelyingPartyRegistration::getEntityId)
                .returns(NAME_ID, RelyingPartyRegistration::getNameIdFormat)
                // from functions
                .returns("{baseUrl}/saml/SSO/alias/entityIdAlias", RelyingPartyRegistration::getAssertionConsumerServiceLocation)
                .returns("{baseUrl}/saml/SingleLogout/alias/entityIdAlias", RelyingPartyRegistration::getSingleLogoutServiceResponseLocation)
                // from xml
                .extracting(RelyingPartyRegistration::getAssertingPartyDetails)
                .returns("https://idp-saml.ua3.int/simplesaml/saml2/idp/metadata.php", RelyingPartyRegistration.AssertingPartyDetails::getEntityId);
    }

    @Test
    void fallsBackToUaaWideValuesWhenNotProvided() {
        repository = spy(new ConfiguratorRelyingPartyRegistrationRepository(ENTITY_ID,
                null, configurator, List.of(), DEFAULT_NAME_ID));
        when(repository.retrieveZone()).thenReturn(identityZone);
        when(identityZone.isUaa()).thenReturn(true);
        when(identityZone.getConfig()).thenReturn(identityZoneConfiguration);
        when(identityZoneConfiguration.getSamlConfig()).thenReturn(samlConfig);
        when(definition.getIdpEntityAlias()).thenReturn(REGISTRATION_ID);
        when(definition.getMetaDataLocation()).thenReturn("saml-sample-metadata.xml");
        when(configurator.getIdentityProviderDefinitionsForZone(identityZone)).thenReturn(List.of(definition));

        RelyingPartyRegistration registration = repository.findByRegistrationId(REGISTRATION_ID);
        assertThat(registration)
                // from definition
                .returns(REGISTRATION_ID, RelyingPartyRegistration::getRegistrationId)
                .returns(ENTITY_ID, RelyingPartyRegistration::getEntityId)
                .returns(DEFAULT_NAME_ID, RelyingPartyRegistration::getNameIdFormat)
                // from functions
                .returns("{baseUrl}/saml/SSO/alias/entityId", RelyingPartyRegistration::getAssertionConsumerServiceLocation)
                .returns("{baseUrl}/saml/SingleLogout/alias/entityId", RelyingPartyRegistration::getSingleLogoutServiceResponseLocation);
    }

    @Test
    void buildsCorrectRegistrationWhenZoneIdIsStored() {
        when(repository.retrieveZone()).thenReturn(identityZone);
        when(identityZone.isUaa()).thenReturn(false);
        when(identityZone.getSubdomain()).thenReturn(ZONE_DOMAIN);
        when(identityZone.getConfig()).thenReturn(identityZoneConfiguration);
        when(identityZoneConfiguration.getSamlConfig()).thenReturn(samlConfig);
        when(definition.getIdpEntityAlias()).thenReturn(REGISTRATION_ID);
        when(definition.getNameID()).thenReturn(NAME_ID);
        when(definition.getMetaDataLocation()).thenReturn("saml-sample-metadata.xml");
        when(configurator.getIdentityProviderDefinitionsForZone(identityZone)).thenReturn(List.of(definition));

        RelyingPartyRegistration registration = repository.findByRegistrationId(REGISTRATION_ID);
        assertThat(registration)
                // from definition
                .returns(REGISTRATION_ID, RelyingPartyRegistration::getRegistrationId)
                .returns(ZONED_ENTITY_ID, RelyingPartyRegistration::getEntityId)
                .returns(NAME_ID, RelyingPartyRegistration::getNameIdFormat)
                // from functions
                .returns("{baseUrl}/saml/SSO/alias/zoneDomain.entityIdAlias", RelyingPartyRegistration::getAssertionConsumerServiceLocation)
                .returns("{baseUrl}/saml/SingleLogout/alias/zoneDomain.entityIdAlias", RelyingPartyRegistration::getSingleLogoutServiceResponseLocation)
                // from xml
                .extracting(RelyingPartyRegistration::getAssertingPartyDetails)
                .returns("https://idp-saml.ua3.int/simplesaml/saml2/idp/metadata.php", RelyingPartyRegistration.AssertingPartyDetails::getEntityId)
                // signature algorithm defaults to SHA256
                .extracting(RelyingPartyRegistration.AssertingPartyDetails::getSigningAlgorithms)
                .isEqualTo(List.of(ALGO_ID_SIGNATURE_RSA_SHA256));
    }

    @Test
    void buildsCorrectRegistrationWithZoneEntityIdSet() {
        repository = spy(new ConfiguratorRelyingPartyRegistrationRepository(ENTITY_ID,
                null, configurator, List.of(), DEFAULT_NAME_ID));
        when(repository.retrieveZone()).thenReturn(identityZone);
        when(identityZone.isUaa()).thenReturn(false);
        when(identityZone.getSubdomain()).thenReturn(ZONE_DOMAIN);
        when(identityZone.getConfig()).thenReturn(identityZoneConfiguration);
        when(identityZoneConfiguration.getSamlConfig()).thenReturn(samlConfig);
        when(samlConfig.getEntityID()).thenReturn(ZONE_SPECIFIC_ENTITY_ID);
        when(definition.getIdpEntityAlias()).thenReturn(REGISTRATION_ID);
        when(definition.getNameID()).thenReturn(NAME_ID);
        when(definition.getMetaDataLocation()).thenReturn("saml-sample-metadata.xml");
        when(configurator.getIdentityProviderDefinitionsForZone(identityZone)).thenReturn(List.of(definition));

        RelyingPartyRegistration registration = repository.findByRegistrationId(REGISTRATION_ID);
        assertThat(registration)
                // from definition
                .returns(REGISTRATION_ID, RelyingPartyRegistration::getRegistrationId)
                .returns(ZONE_SPECIFIC_ENTITY_ID, RelyingPartyRegistration::getEntityId)
                .returns(NAME_ID, RelyingPartyRegistration::getNameIdFormat)
                // from functions
                .returns("{baseUrl}/saml/SSO/alias/zoneDomain.entityId", RelyingPartyRegistration::getAssertionConsumerServiceLocation)
                .returns("{baseUrl}/saml/SingleLogout/alias/zoneDomain.entityId", RelyingPartyRegistration::getSingleLogoutServiceResponseLocation);
    }

    @Test
    void failsWhenInvalidMetadataLocationIsStored() {
        when(repository.retrieveZone()).thenReturn(identityZone);
        when(identityZone.isUaa()).thenReturn(true);
        when(identityZone.getConfig()).thenReturn(identityZoneConfiguration);
        when(identityZoneConfiguration.getSamlConfig()).thenReturn(samlConfig);

        when(definition.getIdpEntityAlias()).thenReturn(REGISTRATION_ID);
        when(definition.getMetaDataLocation()).thenReturn("not_found_metadata.xml");
        when(configurator.getIdentityProviderDefinitionsForZone(identityZone)).thenReturn(List.of(definition));

        assertThatNoException().isThrownBy(() -> repository.findByRegistrationId(REGISTRATION_ID));
    }

    @Test
    void failsWhenInvalidMetadataXmlIsStored() {
        when(repository.retrieveZone()).thenReturn(identityZone);
        when(identityZone.isUaa()).thenReturn(true);
        when(identityZone.getConfig()).thenReturn(identityZoneConfiguration);
        when(identityZoneConfiguration.getSamlConfig()).thenReturn(samlConfig);

        when(definition.getIdpEntityAlias()).thenReturn(REGISTRATION_ID);
        when(definition.getMetaDataLocation()).thenReturn("<?xml version=\"1.0\"?>\n<xml>invalid xml</xml>");
        when(configurator.getIdentityProviderDefinitionsForZone(identityZone)).thenReturn(List.of(definition));

        assertThatNoException().isThrownBy(() -> repository.findByRegistrationId(REGISTRATION_ID));
    }

    @Test
    void withSha512SignatureAlgorithm() {
        repository = spy(new ConfiguratorRelyingPartyRegistrationRepository(ENTITY_ID, ENTITY_ID_ALIAS, configurator, List.of(SignatureAlgorithm.SHA512), DEFAULT_NAME_ID));
        when(repository.retrieveZone()).thenReturn(identityZone);
        when(identityZone.getConfig()).thenReturn(identityZoneConfiguration);
        when(identityZoneConfiguration.getSamlConfig()).thenReturn(samlConfig);
        when(definition.getIdpEntityAlias()).thenReturn(REGISTRATION_ID);
        when(definition.getMetaDataLocation()).thenReturn("saml-sample-metadata.xml");
        when(configurator.getIdentityProviderDefinitionsForZone(identityZone)).thenReturn(List.of(definition));

        RelyingPartyRegistration registration = repository.findByRegistrationId(REGISTRATION_ID);
        assertThat(registration.getAssertingPartyDetails().getSigningAlgorithms())
                .hasSize(1)
                .first()
                .isEqualTo(ALGO_ID_SIGNATURE_RSA_SHA512);
    }

    private String loadResouceAsString(String resourceLocation) {
        ResourceLoader resourceLoader = new DefaultResourceLoader();
        Resource resource = resourceLoader.getResource(resourceLocation);

        try (Reader reader = new InputStreamReader(resource.getInputStream(), UTF_8)) {
            return FileCopyUtils.copyToString(reader);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
