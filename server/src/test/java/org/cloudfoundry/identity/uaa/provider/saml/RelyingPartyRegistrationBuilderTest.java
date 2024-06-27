package org.cloudfoundry.identity.uaa.provider.saml;

import org.cloudfoundry.identity.uaa.util.KeyWithCert;
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

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RelyingPartyRegistrationBuilderTest {

    private static final String ENTITY_ID = "entityId";
    private static final String NAME_ID = "nameIdFormat";
    private static final String REGISTRATION_ID = "registrationId";
    private static final boolean SIGN_REQUEST = true;

    @Mock
    private KeyWithCert mockKeyWithCert;

    @Test
    void buildsRelyingPartyRegistrationFromLocation() {
        when(mockKeyWithCert.getCertificate()).thenReturn(mock(X509Certificate.class));
        when(mockKeyWithCert.getPrivateKey()).thenReturn(mock(PrivateKey.class));

        RelyingPartyRegistration registration = RelyingPartyRegistrationBuilder
                .buildRelyingPartyRegistration(ENTITY_ID, NAME_ID, SIGN_REQUEST, mockKeyWithCert, "saml-sample-metadata.xml", REGISTRATION_ID);
        assertThat(registration)
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
    void buildsRelyingPartyRegistrationFromXML() {
        when(mockKeyWithCert.getCertificate()).thenReturn(mock(X509Certificate.class));
        when(mockKeyWithCert.getPrivateKey()).thenReturn(mock(PrivateKey.class));

        String metadataXml = loadResouceAsString("saml-sample-metadata.xml");
        RelyingPartyRegistration registration = RelyingPartyRegistrationBuilder
                .buildRelyingPartyRegistration(ENTITY_ID, NAME_ID, SIGN_REQUEST, mockKeyWithCert, metadataXml, REGISTRATION_ID);

        assertThat(registration)
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
    void failsWithInvalidXML() {
        String metadataXml = "<?xml version=\"1.0\"?>\n<xml>invalid xml</xml>";
        assertThatThrownBy(() ->
                RelyingPartyRegistrationBuilder.buildRelyingPartyRegistration(ENTITY_ID, NAME_ID,
                        SIGN_REQUEST, mockKeyWithCert, metadataXml, REGISTRATION_ID))
                .isInstanceOf(Saml2Exception.class)
                .hasMessageContaining("Unsupported element");
    }

    private static String loadResouceAsString(String resourceLocation) {
        ResourceLoader resourceLoader = new DefaultResourceLoader();
        Resource resource = resourceLoader.getResource(resourceLocation);

        try (Reader reader = new InputStreamReader(resource.getInputStream(), UTF_8)) {
            return FileCopyUtils.copyToString(reader);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
