package org.cloudfoundry.identity.uaa.provider.saml;

import org.cloudfoundry.identity.uaa.util.KeyWithCert;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.util.FileCopyUtils;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.UncheckedIOException;
import java.util.List;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.cloudfoundry.identity.uaa.provider.saml.TestCredentialObjects.keyWithCert1;
import static org.cloudfoundry.identity.uaa.provider.saml.TestCredentialObjects.keyWithCert2;
import static org.cloudfoundry.identity.uaa.provider.saml.TestCredentialObjects.x509Certificate1;
import static org.cloudfoundry.identity.uaa.provider.saml.TestCredentialObjects.x509Certificate2;

class RelyingPartyRegistrationBuilderTest {

    private static final String ENTITY_ID = "entityId";
    private static final String ENTITY_ID_ALIAS = "entityIdAlias";
    private static final String NAME_ID = "nameIdFormat";
    private static final String REGISTRATION_ID = "registrationId";
    private static final String SAML_SAMPLE_METADATA_XML = "saml-sample-metadata.xml";

    @Test
    void buildsRelyingPartyRegistrationFromLocation() {
        RelyingPartyRegistrationBuilder.Params params = RelyingPartyRegistrationBuilder.Params.builder()
                .samlEntityID(ENTITY_ID)
                .samlSpNameId(NAME_ID)
                .keys(List.of(keyWithCert1()))
                .metadataLocation(SAML_SAMPLE_METADATA_XML)
                .rpRegistrationId(REGISTRATION_ID)
                .samlSpAlias(ENTITY_ID_ALIAS)
                .requestSigned(true)
                .signatureAlgorithms(List.of())
                .build();
        RelyingPartyRegistration registration = RelyingPartyRegistrationBuilder.buildRelyingPartyRegistration(params);

        assertThat(registration)
                .returns(REGISTRATION_ID, RelyingPartyRegistration::getRegistrationId)
                .returns(ENTITY_ID, RelyingPartyRegistration::getEntityId)
                .returns(NAME_ID, RelyingPartyRegistration::getNameIdFormat)
                // from functions
                .returns("{baseUrl}/saml/SSO/alias/entityIdAlias", RelyingPartyRegistration::getAssertionConsumerServiceLocation)
                .returns("{baseUrl}/saml/SingleLogout/alias/entityIdAlias", RelyingPartyRegistration::getSingleLogoutServiceResponseLocation)
                // from xml
                .extracting(RelyingPartyRegistration::getAssertingPartyDetails)
                .returns("https://idp-saml.ua3.int/simplesaml/saml2/idp/metadata.php", RelyingPartyRegistration.AssertingPartyDetails::getEntityId)
                .returns(true, RelyingPartyRegistration.AssertingPartyDetails::getWantAuthnRequestsSigned);
    }

    @Test
    void buildsRelyingPartyRegistrationFromXML() {
        String metadataXml = loadResouceAsString(SAML_SAMPLE_METADATA_XML);

        RelyingPartyRegistrationBuilder.Params params = RelyingPartyRegistrationBuilder.Params.builder()
                .samlEntityID(ENTITY_ID)
                .samlSpNameId(NAME_ID)
                .keys(List.of(keyWithCert1()))
                .metadataLocation(metadataXml)
                .rpRegistrationId(REGISTRATION_ID)
                .samlSpAlias(ENTITY_ID_ALIAS)
                .requestSigned(false)
                .signatureAlgorithms(List.of())
                .build();
        RelyingPartyRegistration registration = RelyingPartyRegistrationBuilder.buildRelyingPartyRegistration(params);

        assertThat(registration)
                .returns(REGISTRATION_ID, RelyingPartyRegistration::getRegistrationId)
                .returns(ENTITY_ID, RelyingPartyRegistration::getEntityId)
                .returns(NAME_ID, RelyingPartyRegistration::getNameIdFormat)
                // from functions
                .returns("{baseUrl}/saml/SSO/alias/entityIdAlias", RelyingPartyRegistration::getAssertionConsumerServiceLocation)
                .returns("{baseUrl}/saml/SingleLogout/alias/entityIdAlias", RelyingPartyRegistration::getSingleLogoutServiceResponseLocation)
                // from xml
                .extracting(RelyingPartyRegistration::getAssertingPartyDetails)
                .returns("https://idp-saml.ua3.int/simplesaml/saml2/idp/metadata.php", RelyingPartyRegistration.AssertingPartyDetails::getEntityId)
                .returns(false, RelyingPartyRegistration.AssertingPartyDetails::getWantAuthnRequestsSigned);
    }

    @Test
    void withCredentials() {
        String metadataXml = loadResouceAsString(SAML_SAMPLE_METADATA_XML);

        RelyingPartyRegistrationBuilder.Params params = RelyingPartyRegistrationBuilder.Params.builder()
                .samlEntityID(ENTITY_ID)
                .samlSpNameId(NAME_ID)
                .keys(List.of(keyWithCert1(), keyWithCert2()))
                .metadataLocation(metadataXml)
                .rpRegistrationId(REGISTRATION_ID)
                .samlSpAlias(ENTITY_ID_ALIAS)
                .requestSigned(false)
                .signatureAlgorithms(List.of(SignatureAlgorithm.SHA512, SignatureAlgorithm.SHA256))
                .build();
        RelyingPartyRegistration registration = RelyingPartyRegistrationBuilder.buildRelyingPartyRegistration(params);

        assertThat(registration.getSigningX509Credentials())
                .hasSize(2)
                .extracting(Saml2X509Credential::getCertificate)
                .containsOnly(x509Certificate1(), x509Certificate2());

        assertThat(registration.getDecryptionX509Credentials())
                .hasSize(1)
                .extracting(Saml2X509Credential::getCertificate)
                .containsOnly(x509Certificate1());

        assertThat(registration.getAssertingPartyDetails().getSigningAlgorithms())
                .hasSize(2)
                .containsOnly(SignatureAlgorithm.SHA512.getSignatureAlgorithmURI(), SignatureAlgorithm.SHA256.getSignatureAlgorithmURI());
    }

    @Test
    void failsWithInvalidXML() {
        String metadataXml = "<?xml version=\"1.0\"?>\n<xml>invalid xml</xml>";
        List<KeyWithCert> keyList = List.of(keyWithCert1());
        List<SignatureAlgorithm> signatureAlgorithms = List.of();

        RelyingPartyRegistrationBuilder.Params params = RelyingPartyRegistrationBuilder.Params.builder()
                .samlEntityID(ENTITY_ID)
                .samlSpNameId(NAME_ID)
                .keys(keyList)
                .metadataLocation(metadataXml)
                .rpRegistrationId(REGISTRATION_ID)
                .samlSpAlias(ENTITY_ID_ALIAS)
                .requestSigned(true)
                .signatureAlgorithms(signatureAlgorithms)
                .build();

        assertThatThrownBy(() ->
                RelyingPartyRegistrationBuilder.buildRelyingPartyRegistration(params))
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
