package org.cloudfoundry.identity.uaa.provider.saml;

import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.util.KeyWithCert;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.util.FileCopyUtils;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.UncheckedIOException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ConfiguratorRelyingPartyRegistrationRepositoryTest {
    private static final String ENTITY_ID = "entityId";
    private static final String REGISTRATION_ID = "registrationId";
    private static final String NAME_ID = "name1";

    @Mock
    private SamlIdentityProviderConfigurator mockConfigurator;

    @Mock
    private KeyWithCert mockKeyWithCert;

    private ConfiguratorRelyingPartyRegistrationRepository repository;

    @BeforeEach
    void setUp() {
        repository = new ConfiguratorRelyingPartyRegistrationRepository(true, ENTITY_ID, mockKeyWithCert,
                mockConfigurator);
    }

    @Test
    void constructorWithNullConfiguratorThrows() {
        assertThatThrownBy(() -> new ConfiguratorRelyingPartyRegistrationRepository(
                true, ENTITY_ID, mockKeyWithCert, null)
        ).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void findByRegistrationIdWithMultipleInDb() {
        when(mockKeyWithCert.getCertificate()).thenReturn(mock(X509Certificate.class));
        when(mockKeyWithCert.getPrivateKey()).thenReturn(mock(PrivateKey.class));

        //definition 1
        SamlIdentityProviderDefinition definition = mock(SamlIdentityProviderDefinition.class);
        when(definition.getIdpEntityAlias()).thenReturn(REGISTRATION_ID);
        when(definition.getNameID()).thenReturn(NAME_ID);
        when(definition.getMetaDataLocation()).thenReturn("saml-sample-metadata.xml");

        //other definitions
        SamlIdentityProviderDefinition otherDefinition = mock(SamlIdentityProviderDefinition.class);
        when(otherDefinition.getIdpEntityAlias()).thenReturn("otherRegistrationId");
        SamlIdentityProviderDefinition anotherDefinition = mock(SamlIdentityProviderDefinition.class);

        when(mockConfigurator.getIdentityProviderDefinitions()).thenReturn(Arrays.asList(otherDefinition, definition, anotherDefinition));
        RelyingPartyRegistration registration = repository.findByRegistrationId(REGISTRATION_ID);
        assertThat(registration)
                // from definition
                .returns(REGISTRATION_ID, RelyingPartyRegistration::getRegistrationId)
                .returns(ENTITY_ID, RelyingPartyRegistration::getEntityId)
                .returns(NAME_ID, RelyingPartyRegistration::getNameIdFormat)
                // from functions
                .returns("{baseUrl}/saml/SSO/alias/entityId", RelyingPartyRegistration::getAssertionConsumerServiceLocation)
                .returns("{baseUrl}/saml/SingleLogout/alias/entityId", RelyingPartyRegistration::getSingleLogoutServiceResponseLocation)
                // from xml
                .extracting(RelyingPartyRegistration::getAssertingPartyDetails)
                .returns("https://idp-saml.ua3.int/simplesaml/saml2/idp/metadata.php", RelyingPartyRegistration.AssertingPartyDetails::getEntityId);
    }

    @Test
    void findByRegistrationIdWhenNoneFound() {
        SamlIdentityProviderDefinition definition = mock(SamlIdentityProviderDefinition.class);
        when(definition.getIdpEntityAlias()).thenReturn(REGISTRATION_ID);
        when(mockConfigurator.getIdentityProviderDefinitions()).thenReturn(List.of(definition));

        assertThat(repository.findByRegistrationId("registrationIdNotFound")).isNull();
    }

    @Test
    void buildsCorrectRegistrationWhenMetadataXmlIsStored() {
        String metadata = loadResouceAsString("no_single_logout_service-metadata.xml");
        when(mockKeyWithCert.getCertificate()).thenReturn(mock(X509Certificate.class));
        when(mockKeyWithCert.getPrivateKey()).thenReturn(mock(PrivateKey.class));
        SamlIdentityProviderDefinition definition = mock(SamlIdentityProviderDefinition.class);
        when(definition.getIdpEntityAlias()).thenReturn("no_slos");
        when(definition.getNameID()).thenReturn(NAME_ID);
        when(definition.getMetaDataLocation()).thenReturn(metadata);
        when(mockConfigurator.getIdentityProviderDefinitions()).thenReturn(List.of(definition));

        RelyingPartyRegistration registration = repository.findByRegistrationId("no_slos");

        assertThat(registration)
                // from definition
                .returns("no_slos", RelyingPartyRegistration::getRegistrationId)
                .returns(ENTITY_ID, RelyingPartyRegistration::getEntityId)
                .returns(NAME_ID, RelyingPartyRegistration::getNameIdFormat)
                // from functions
                .returns("{baseUrl}/saml/SSO/alias/entityId", RelyingPartyRegistration::getAssertionConsumerServiceLocation)
                .returns("{baseUrl}/saml/SingleLogout/alias/entityId", RelyingPartyRegistration::getSingleLogoutServiceResponseLocation)
                // from xml
                .extracting(RelyingPartyRegistration::getAssertingPartyDetails)
                .returns("http://uaa-acceptance.cf-app.com/saml-idp", RelyingPartyRegistration.AssertingPartyDetails::getEntityId);
    }

    @Test
    void buildsCorrectRegistrationWhenMetadataLocationIsStored() {
        when(mockKeyWithCert.getCertificate()).thenReturn(mock(X509Certificate.class));
        when(mockKeyWithCert.getPrivateKey()).thenReturn(mock(PrivateKey.class));
        SamlIdentityProviderDefinition definition = mock(SamlIdentityProviderDefinition.class);
        when(definition.getIdpEntityAlias()).thenReturn("no_slos");
        when(definition.getNameID()).thenReturn(NAME_ID);
        when(definition.getMetaDataLocation()).thenReturn("no_single_logout_service-metadata.xml");
        when(mockConfigurator.getIdentityProviderDefinitions()).thenReturn(List.of(definition));

        RelyingPartyRegistration registration = repository.findByRegistrationId("no_slos");
        assertThat(registration)
                // from definition
                .returns("no_slos", RelyingPartyRegistration::getRegistrationId)
                .returns(ENTITY_ID, RelyingPartyRegistration::getEntityId)
                .returns(NAME_ID, RelyingPartyRegistration::getNameIdFormat)
                // from functions
                .returns("{baseUrl}/saml/SSO/alias/entityId", RelyingPartyRegistration::getAssertionConsumerServiceLocation)
                .returns("{baseUrl}/saml/SingleLogout/alias/entityId", RelyingPartyRegistration::getSingleLogoutServiceResponseLocation)
                // from xml
                .extracting(RelyingPartyRegistration::getAssertingPartyDetails)
                .returns("http://uaa-acceptance.cf-app.com/saml-idp", RelyingPartyRegistration.AssertingPartyDetails::getEntityId);
    }

    @Test
    void failsWhenInvalidMetadataLocationIsStored() {
        SamlIdentityProviderDefinition definition = mock(SamlIdentityProviderDefinition.class);
        when(definition.getIdpEntityAlias()).thenReturn(REGISTRATION_ID);
        when(definition.getMetaDataLocation()).thenReturn("not_found_metadata.xml");
        when(mockConfigurator.getIdentityProviderDefinitions()).thenReturn(List.of(definition));

        assertThatThrownBy(() -> repository.findByRegistrationId(REGISTRATION_ID))
                .isInstanceOf(Saml2Exception.class)
                .hasMessageContaining("not_found_metadata.xml");
    }

    @Test
    void failsWhenInvalidMetadataXmlIsStored() {
        SamlIdentityProviderDefinition definition = mock(SamlIdentityProviderDefinition.class);
        when(definition.getIdpEntityAlias()).thenReturn(REGISTRATION_ID);
        when(definition.getMetaDataLocation()).thenReturn("<?xml version=\"1.0\"?>\n<xml>invalid xml</xml>");
        when(mockConfigurator.getIdentityProviderDefinitions()).thenReturn(List.of(definition));

        assertThatThrownBy(() -> repository.findByRegistrationId(REGISTRATION_ID))
                .isInstanceOf(Saml2Exception.class)
                .hasMessageContaining("Unsupported element");
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
