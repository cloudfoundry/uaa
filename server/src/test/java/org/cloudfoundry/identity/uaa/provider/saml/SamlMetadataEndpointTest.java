package org.cloudfoundry.identity.uaa.provider.saml;

import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.SamlConfig;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.xmlunit.assertj.XmlAssert;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.provider.saml.Saml2TestUtils.xmlNamespaces;
import static org.cloudfoundry.identity.uaa.provider.saml.TestSaml2X509Credentials.relyingPartySigningCredential;
import static org.cloudfoundry.identity.uaa.provider.saml.TestSaml2X509Credentials.relyingPartyVerifyingCredential;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SamlMetadataEndpointTest {
    private static final String ASSERTION_CONSUMER_SERVICE = "https://acsl";
    private static final String REGISTRATION_ID = "regId";
    private static final String ENTITY_ID = "entityId";

    SamlMetadataEndpoint endpoint;

    @Mock
    RelyingPartyRegistrationRepository repository;
    @Mock
    IdentityZoneManager identityZoneManager;
    @Mock
    RelyingPartyRegistration registration;
    @Mock
    IdentityZone identityZone;
    @Mock
    IdentityZoneConfiguration identityZoneConfiguration;
    @Mock
    SamlConfig samlConfig;

    @BeforeEach
    void setUp() {
        endpoint = spy(new SamlMetadataEndpoint(repository, identityZoneManager));
        when(repository.findByRegistrationId(REGISTRATION_ID)).thenReturn(registration);
        when(registration.getEntityId()).thenReturn(ENTITY_ID);
        when(registration.getSigningX509Credentials()).thenReturn(List.of(relyingPartySigningCredential()));
        when(registration.getDecryptionX509Credentials()).thenReturn(List.of(relyingPartyVerifyingCredential()));
        when(registration.getAssertionConsumerServiceBinding()).thenReturn(Saml2MessageBinding.REDIRECT);
        when(registration.getAssertionConsumerServiceLocation()).thenReturn(ASSERTION_CONSUMER_SERVICE);
        when(identityZoneManager.getCurrentIdentityZone()).thenReturn(identityZone);
        when(identityZone.getConfig()).thenReturn(identityZoneConfiguration);
        when(identityZoneConfiguration.getSamlConfig()).thenReturn(samlConfig);
    }

    @Test
    void testDefaultFileName() {
        ResponseEntity<String> response = endpoint.metadataEndpoint(REGISTRATION_ID);
        assertThat(response.getHeaders().getFirst(HttpHeaders.CONTENT_DISPOSITION))
                .isEqualTo("attachment; filename=\"saml-sp.xml\"; filename*=UTF-8''saml-sp.xml");
    }

    @Test
    void testZonedFileName() {
        when(identityZone.isUaa()).thenReturn(false);
        when(identityZone.getSubdomain()).thenReturn("testzone1");
        when(endpoint.retrieveZone()).thenReturn(identityZone);

        ResponseEntity<String> response = endpoint.metadataEndpoint(REGISTRATION_ID);
        assertThat(response.getHeaders().getFirst(HttpHeaders.CONTENT_DISPOSITION))
                .isEqualTo("attachment; filename=\"saml-testzone1-sp.xml\"; filename*=UTF-8''saml-testzone1-sp.xml");
    }

    @Test
    void testDefaultMetadataXml() {
        when(samlConfig.isWantAssertionSigned()).thenReturn(true);
        when(samlConfig.isRequestSigned()).thenReturn(true);

        ResponseEntity<String> response = endpoint.metadataEndpoint(REGISTRATION_ID);
        XmlAssert xmlAssert =XmlAssert.assertThat(response.getBody()).withNamespaceContext(xmlNamespaces());
        xmlAssert.valueByXPath("//md:EntityDescriptor/@entityID").isEqualTo(ENTITY_ID);
        xmlAssert.valueByXPath("//md:SPSSODescriptor/@AuthnRequestsSigned").isEqualTo(true);
        xmlAssert.valueByXPath("//md:SPSSODescriptor/@WantAssertionsSigned").isEqualTo(true);
        xmlAssert.valueByXPath("//md:AssertionConsumerService/@Location").isEqualTo(ASSERTION_CONSUMER_SERVICE);
    }

    @Test
    void testDefaultMetadataXml_alternateValues() {
        when(samlConfig.isWantAssertionSigned()).thenReturn(false);
        when(samlConfig.isRequestSigned()).thenReturn(false);

        ResponseEntity<String> response = endpoint.metadataEndpoint(REGISTRATION_ID);
        XmlAssert xmlAssert =XmlAssert.assertThat(response.getBody()).withNamespaceContext(xmlNamespaces());
        xmlAssert.valueByXPath("//md:SPSSODescriptor/@AuthnRequestsSigned").isEqualTo(false);
        xmlAssert.valueByXPath("//md:SPSSODescriptor/@WantAssertionsSigned").isEqualTo(false);
    }
}
