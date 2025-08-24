package org.cloudfoundry.identity.uaa.provider.saml;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.SamlConfig;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.xmlunit.assertj.XmlAssert;

import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.util.List;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.provider.saml.Saml2TestUtils.xmlNamespaces;
import static org.cloudfoundry.identity.uaa.provider.saml.SamlNameIdFormats.NAMEID_FORMAT_EMAIL;
import static org.cloudfoundry.identity.uaa.provider.saml.SamlNameIdFormats.NAMEID_FORMAT_PERSISTENT;
import static org.cloudfoundry.identity.uaa.provider.saml.SamlNameIdFormats.NAMEID_FORMAT_TRANSIENT;
import static org.cloudfoundry.identity.uaa.provider.saml.SamlNameIdFormats.NAMEID_FORMAT_UNSPECIFIED;
import static org.cloudfoundry.identity.uaa.provider.saml.SamlNameIdFormats.NAMEID_FORMAT_X509SUBJECT;
import static org.cloudfoundry.identity.uaa.provider.saml.TestCredentialObjects.encodedCertificate;
import static org.cloudfoundry.identity.uaa.provider.saml.TestCredentialObjects.formatCert;
import static org.cloudfoundry.identity.uaa.provider.saml.TestSaml2X509Credentials.relyingPartySigningCredential;
import static org.cloudfoundry.identity.uaa.provider.saml.TestSaml2X509Credentials.relyingPartyVerifyingCredential;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;
import static org.opensaml.xmlsec.signature.support.SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS;
import static org.opensaml.xmlsec.signature.support.SignatureConstants.ALGO_ID_DIGEST_SHA1;
import static org.opensaml.xmlsec.signature.support.SignatureConstants.ALGO_ID_DIGEST_SHA256;
import static org.opensaml.xmlsec.signature.support.SignatureConstants.ALGO_ID_DIGEST_SHA512;
import static org.opensaml.xmlsec.signature.support.SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1;
import static org.opensaml.xmlsec.signature.support.SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256;
import static org.opensaml.xmlsec.signature.support.SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA512;
import static org.opensaml.xmlsec.signature.support.SignatureConstants.TRANSFORM_C14N_EXCL_OMIT_COMMENTS;
import static org.opensaml.xmlsec.signature.support.SignatureConstants.TRANSFORM_ENVELOPED_SIGNATURE;

@ExtendWith(MockitoExtension.class)
class SamlMetadataEndpointTest {
    private static final String ASSERTION_CONSUMER_SERVICE_1 = "http://localhost:8080/saml/SSO/alias/entityAlias";
    private static final String ASSERTION_CONSUMER_SERVICE_2 = "http://localhost:8080/oauth/token/alias/entityAlias";
    private static final String REGISTRATION_ID = SamlMetadataEndpoint.DEFAULT_REGISTRATION_ID;
    private static final String ENTITY_ID = "entityId";
    private static final String TEST_ZONE = "testzone1";

    SamlMetadataEndpoint endpoint;

    @Mock
    RelyingPartyRegistrationResolver resolver;
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
    @Mock
    SamlKeyManagerFactory keyManagerFactory;

    MockHttpServletRequest request;

    @BeforeAll
    static void beforeAll() {
        Security.addProvider(new BouncyCastleFipsProvider());
    }

    @BeforeEach
    void beforeEach() {
        request = new MockHttpServletRequest();
        endpoint = spy(new SamlMetadataEndpoint(resolver, identityZoneManager, SignatureAlgorithm.SHA256, true));
        when(registration.getEntityId()).thenReturn(ENTITY_ID);
        when(registration.getSigningX509Credentials()).thenReturn(List.of(relyingPartySigningCredential()));
        when(registration.getDecryptionX509Credentials()).thenReturn(List.of(relyingPartyVerifyingCredential()));
        when(registration.getAssertionConsumerServiceBinding()).thenReturn(Saml2MessageBinding.REDIRECT);
        when(registration.getAssertionConsumerServiceLocation()).thenReturn(ASSERTION_CONSUMER_SERVICE_1);
        when(identityZoneManager.getCurrentIdentityZone()).thenReturn(identityZone);
        when(identityZone.getConfig()).thenReturn(identityZoneConfiguration);
        when(identityZoneConfiguration.getSamlConfig()).thenReturn(samlConfig);
        IdentityZoneHolder.setSamlKeyManagerFactory(keyManagerFactory);
    }

    @Test
    void defaultZoneFileName() {
        when(resolver.resolve(request, REGISTRATION_ID)).thenReturn(registration);

        ResponseEntity<String> response = endpoint.metadataEndpoint(request);
        assertThat(response.getHeaders().getFirst(HttpHeaders.CONTENT_DISPOSITION))
                .isEqualTo("attachment; filename=\"saml-sp.xml\"; filename*=UTF-8''saml-sp.xml");
    }

    @Test
    void nonDefaultZoneFileName() {
        when(resolver.resolve(request, REGISTRATION_ID)).thenReturn(registration);
        when(identityZone.isUaa()).thenReturn(false);
        when(identityZone.getSubdomain()).thenReturn(TEST_ZONE);
        when(endpoint.retrieveZone()).thenReturn(identityZone);

        ResponseEntity<String> response = endpoint.metadataEndpoint(request);
        assertThat(response.getHeaders().getFirst(HttpHeaders.CONTENT_DISPOSITION))
                .isEqualTo("attachment; filename=\"saml-%1$s-sp.xml\"; filename*=UTF-8''saml-%1$s-sp.xml".formatted(TEST_ZONE));
    }

    @Test
    void defaultMetadataXml() {
        when(resolver.resolve(request, REGISTRATION_ID)).thenReturn(registration);
        when(samlConfig.isWantAssertionSigned()).thenReturn(true);
        when(samlConfig.isRequestSigned()).thenReturn(true);

        ResponseEntity<String> response = endpoint.metadataEndpoint(request);
        XmlAssert xmlAssert = XmlAssert.assertThat(response.getBody()).withNamespaceContext(xmlNamespaces());
        xmlAssert.valueByXPath("//md:EntityDescriptor/@entityID").isEqualTo(ENTITY_ID);
        xmlAssert.valueByXPath("//md:EntityDescriptor/@ID").isEqualTo(ENTITY_ID);
        xmlAssert.valueByXPath("//md:SPSSODescriptor/@AuthnRequestsSigned").isEqualTo(true);
        xmlAssert.valueByXPath("//md:SPSSODescriptor/@WantAssertionsSigned").isEqualTo(true);
        xmlAssert.nodesByXPath("//md:AssertionConsumerService")
                .extractingAttribute("Location")
                .containsExactly(ASSERTION_CONSUMER_SERVICE_1, ASSERTION_CONSUMER_SERVICE_2);
        xmlAssert.nodesByXPath("//md:AssertionConsumerService")
                .extractingAttribute("Binding")
                .containsExactly(Saml2MessageBinding.REDIRECT.getUrn(), "urn:oasis:names:tc:SAML:2.0:bindings:URI");
        xmlAssert.nodesByXPath("//md:NameIDFormat")
                .extractingText()
                .containsExactlyInAnyOrder(NAMEID_FORMAT_EMAIL, NAMEID_FORMAT_PERSISTENT,
                        NAMEID_FORMAT_TRANSIENT, NAMEID_FORMAT_UNSPECIFIED, NAMEID_FORMAT_X509SUBJECT);
    }

    @Test
    void defaultMetadataXml_alternateValues() {
        when(resolver.resolve(request, REGISTRATION_ID)).thenReturn(registration);
        when(samlConfig.isWantAssertionSigned()).thenReturn(false);
        when(samlConfig.isRequestSigned()).thenReturn(false);

        ResponseEntity<String> response = endpoint.metadataEndpoint(request);
        XmlAssert xmlAssert = XmlAssert.assertThat(response.getBody()).withNamespaceContext(xmlNamespaces());
        xmlAssert.valueByXPath("//md:SPSSODescriptor/@AuthnRequestsSigned").isEqualTo(false);
        xmlAssert.valueByXPath("//md:SPSSODescriptor/@WantAssertionsSigned").isEqualTo(false);
    }

    @Test
    void unsigned() {
        endpoint = spy(new SamlMetadataEndpoint(resolver, identityZoneManager, SignatureAlgorithm.SHA1, false));
        when(resolver.resolve(request, REGISTRATION_ID)).thenReturn(registration);

        ResponseEntity<String> response = endpoint.metadataEndpoint(request);
        XmlAssert.assertThat(response.getBody()).withNamespaceContext(xmlNamespaces())
                .nodesByXPath("/md:EntityDescriptor/ds:Signature").doNotExist();
    }

    @Test
    void unsignedIfNoAlgorithm() {
        endpoint = spy(new SamlMetadataEndpoint(resolver, identityZoneManager, null, true));
        when(resolver.resolve(request, REGISTRATION_ID)).thenReturn(registration);

        ResponseEntity<String> response = endpoint.metadataEndpoint(request);
        XmlAssert.assertThat(response.getBody()).withNamespaceContext(xmlNamespaces())
                .nodesByXPath("/md:EntityDescriptor/ds:Signature").doNotExist();
    }

    @Test
    void sha256Signature() throws CertificateEncodingException {
        when(resolver.resolve(request, REGISTRATION_ID)).thenReturn(registration);

        ResponseEntity<String> response = endpoint.metadataEndpoint(request);
        System.out.println(response.getBody());
        XmlAssert xmlAssert = XmlAssert.assertThat(response.getBody()).withNamespaceContext(xmlNamespaces());
        xmlAssert.valueByXPath("/md:EntityDescriptor/@ID").isEqualTo(ENTITY_ID);
        xmlAssert.valueByXPath("/md:EntityDescriptor/ds:Signature/ds:SignedInfo/ds:SignatureMethod/@Algorithm").isEqualTo(ALGO_ID_SIGNATURE_RSA_SHA256);
        xmlAssert.valueByXPath("/md:EntityDescriptor/ds:Signature/ds:SignedInfo/ds:CanonicalizationMethod/@Algorithm").isEqualTo(ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        xmlAssert.valueByXPath("/md:EntityDescriptor/ds:Signature/ds:SignedInfo/ds:Reference/@URI").isEqualTo("#" + ENTITY_ID);
        xmlAssert.nodesByXPath("/md:EntityDescriptor/ds:Signature/ds:SignedInfo/ds:Reference/ds:Transforms/ds:Transform")
                .extractingAttribute("Algorithm")
                .containsExactlyInAnyOrder(TRANSFORM_C14N_EXCL_OMIT_COMMENTS, TRANSFORM_ENVELOPED_SIGNATURE);
        xmlAssert.valueByXPath("/md:EntityDescriptor/ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestMethod/@Algorithm").isEqualTo(ALGO_ID_DIGEST_SHA256);
        xmlAssert.valueByXPath("/md:EntityDescriptor/ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestValue").isNotEmpty();
        xmlAssert.valueByXPath("/md:EntityDescriptor/ds:Signature/ds:SignatureValue").isNotEmpty();
        xmlAssert.valueByXPath("/md:EntityDescriptor/ds:Signature/ds:KeyInfo/ds:X509Data/ds:X509Certificate")
                .isEqualTo(formatCert(encodedCertificate(relyingPartySigningCredential().getCertificate())));
    }

    @Test
    void sha512Signature() {
        endpoint = spy(new SamlMetadataEndpoint(resolver, identityZoneManager, SignatureAlgorithm.SHA512, true));
        when(resolver.resolve(request, REGISTRATION_ID)).thenReturn(registration);

        ResponseEntity<String> response = endpoint.metadataEndpoint(request);
        XmlAssert xmlAssert = XmlAssert.assertThat(response.getBody()).withNamespaceContext(xmlNamespaces());
        xmlAssert.valueByXPath("/md:EntityDescriptor/ds:Signature/ds:SignedInfo/ds:SignatureMethod/@Algorithm").isEqualTo(ALGO_ID_SIGNATURE_RSA_SHA512);
        xmlAssert.valueByXPath("/md:EntityDescriptor/ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestMethod/@Algorithm").isEqualTo(ALGO_ID_DIGEST_SHA512);
    }

    @Test
    void sha1Signature() {
        endpoint = spy(new SamlMetadataEndpoint(resolver, identityZoneManager, SignatureAlgorithm.SHA1, true));
        when(resolver.resolve(request, REGISTRATION_ID)).thenReturn(registration);

        ResponseEntity<String> response = endpoint.metadataEndpoint(request);
        XmlAssert xmlAssert = XmlAssert.assertThat(response.getBody()).withNamespaceContext(xmlNamespaces());
        xmlAssert.valueByXPath("/md:EntityDescriptor/ds:Signature/ds:SignedInfo/ds:SignatureMethod/@Algorithm").isEqualTo(ALGO_ID_SIGNATURE_RSA_SHA1);
        xmlAssert.valueByXPath("/md:EntityDescriptor/ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestMethod/@Algorithm").isEqualTo(ALGO_ID_DIGEST_SHA1);
    }

    static Stream<Arguments> entityIdForNcNameId() {
        String url = "https://entityId:80/entityId";
        String ncn = "https___entityId_80_entityId";

        return Stream.of(
                arguments("when entityId is null", null, "", "_"),
                arguments("when entityId is empty", "", "", "_"),
                arguments("when entityId starts with non-alpha", "2", "2", "_2"),
                arguments("when entityId starts with an underscore", "_", "_", "_"),
                arguments("when entityId is a url", url, url, ncn)
        );
    }

    @ParameterizedTest(name = "{index} - {0}")
    @MethodSource("entityIdForNcNameId")
    void hasValidNcNameIdAndEntityId(String ignore, String entityId, String expectedEntityId, String expectedNcNameEntityId) {
        when(registration.getEntityId()).thenReturn(entityId);
        when(registration.getAssertionConsumerServiceLocation()).thenReturn(ASSERTION_CONSUMER_SERVICE_1);

        endpoint = spy(new SamlMetadataEndpoint(resolver, identityZoneManager, SignatureAlgorithm.SHA1, true));
        when(resolver.resolve(request, REGISTRATION_ID)).thenReturn(registration);

        ResponseEntity<String> response = endpoint.metadataEndpoint(request);
        XmlAssert xmlAssert = XmlAssert.assertThat(response.getBody()).withNamespaceContext(xmlNamespaces());
        xmlAssert.valueByXPath("/md:EntityDescriptor/@ID").isEqualTo(expectedNcNameEntityId);
        xmlAssert.valueByXPath("/md:EntityDescriptor/@entityID").isEqualTo(expectedEntityId);
    }
}
