package org.cloudfoundry.identity.uaa.provider.saml;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.SamlConfig;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManagerImpl;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.xmlunit.assertj.MultipleNodeAssert;
import org.xmlunit.assertj.XmlAssert;

import java.security.Security;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.provider.saml.Saml2TestUtils.xmlNamespaces;
import static org.cloudfoundry.identity.uaa.provider.saml.TestCredentialObjects.certificate1;
import static org.cloudfoundry.identity.uaa.provider.saml.TestCredentialObjects.certificate2;
import static org.cloudfoundry.identity.uaa.provider.saml.TestCredentialObjects.keyName1;
import static org.cloudfoundry.identity.uaa.provider.saml.TestCredentialObjects.keyName2;
import static org.cloudfoundry.identity.uaa.provider.saml.TestCredentialObjects.legacyKeyName;
import static org.cloudfoundry.identity.uaa.provider.saml.TestCredentialObjects.legacySamlKey;
import static org.cloudfoundry.identity.uaa.provider.saml.TestCredentialObjects.samlKey1;
import static org.cloudfoundry.identity.uaa.provider.saml.TestCredentialObjects.samlKey2;
import static org.mockito.Mockito.spy;

public class SamlMetadataEndpointKeyRotationTests {

    private static final String ZONE_ID = "zone-id";
    private static final String NAME_ID_FORMAT = "nameIdFormat";
    private static final String ENTITY_ID = "entityIdValue";
    private static final String ENTITY_ALIAS = "entityAlias";
    public static final String KEY_DESCRIPTOR_CERTIFICATE_XPATH_FORMAT = "//md:SPSSODescriptor/md:KeyDescriptor[@use='%s']//ds:X509Certificate";

    private static IdentityZoneHolder.Initializer initializer;

    private SamlMetadataEndpoint endpoint;
    private SamlConfig samlConfig;

    private MockHttpServletRequest request;

    @BeforeAll
    static void beforeAll() {
        Security.addProvider(new BouncyCastleFipsProvider());

        SamlConfigProps samlConfigProps = new SamlConfigProps();
        samlConfigProps.setKeys(Map.of(legacyKeyName(), legacySamlKey()));
        samlConfigProps.setActiveKeyId(legacyKeyName());
        samlConfigProps.setEntityIDAlias(ENTITY_ALIAS);
        samlConfigProps.setSignMetaData(true);

        SamlKeyManagerFactory samlKeyManagerFactory = new SamlKeyManagerFactory(samlConfigProps);
        initializer = new IdentityZoneHolder.Initializer(null, samlKeyManagerFactory);
    }

    @BeforeEach
    void beforeEach() {
        IdentityZone otherZone = new IdentityZone();
        otherZone.setId(ZONE_ID);
        otherZone.setName(ZONE_ID);
        otherZone.setSubdomain(ZONE_ID);
        IdentityZoneConfiguration otherZoneDefinition = new IdentityZoneConfiguration();
        otherZone.setConfig(otherZoneDefinition);

        samlConfig = otherZoneDefinition.getSamlConfig();
        samlConfig.setRequestSigned(true);
        samlConfig.setWantAssertionSigned(true);
        samlConfig.setEntityID(ENTITY_ID);
        otherZoneDefinition.setIdpDiscoveryEnabled(true);
        samlConfig.addAndActivateKey(keyName1(), samlKey1());

        IdentityZoneManager identityZoneManager = new IdentityZoneManagerImpl();

        RelyingPartyRegistrationRepository registrationRepository =
                new DefaultRelyingPartyRegistrationRepository("entityId", "entityIdAlias", List.of(), NAME_ID_FORMAT);
        RelyingPartyRegistrationResolver registrationResolver = new UaaRelyingPartyRegistrationResolver(registrationRepository, ENTITY_ID);
        endpoint = spy(new SamlMetadataEndpoint(registrationResolver, identityZoneManager, SignatureAlgorithm.SHA256, true));
        IdentityZoneHolder.set(otherZone);

        request = new MockHttpServletRequest();
    }

    @AfterAll
    static void afterAll() {
        IdentityZoneHolder.clear();
        initializer.reset();
    }

    @Test
    void metadataContainsSamlBearerGrantEndpoint() {
        request.setServerName("zone-id.localhost");
        request.setServerPort(8080);
        request.setContextPath("uaa");

        ResponseEntity<String> response = endpoint.metadataEndpoint(request);
        MultipleNodeAssert acsAssert = XmlAssert.assertThat(response.getBody()).withNamespaceContext(xmlNamespaces()).nodesByXPath("//md:AssertionConsumerService");
        acsAssert.extractingAttribute("Binding").contains("urn:oasis:names:tc:SAML:2.0:bindings:URI");
        acsAssert.extractingAttribute("Location").contains("http://zone-id.localhost:8080/uaa/oauth/token/alias/zone-id.entityIdAlias");
        acsAssert.extractingAttribute("index").contains("1");
    }

    @Test
    void defaultKeys() {
        ResponseEntity<String> response = endpoint.metadataEndpoint(request);
        XmlAssert xmlAssert = XmlAssert.assertThat(response.getBody()).withNamespaceContext(xmlNamespaces());

        assertThatEncryptionKeyHasValues(xmlAssert, certificate1());
        assertThatSigningKeyHasValues(xmlAssert, certificate1());
    }

    @Test
    void multipleKeys() {
        samlConfig.addKey(keyName2(), samlKey2());

        ResponseEntity<String> response = endpoint.metadataEndpoint(request);
        XmlAssert xmlAssert = XmlAssert.assertThat(response.getBody()).withNamespaceContext(xmlNamespaces());

        assertThatEncryptionKeyHasValues(xmlAssert, certificate1());
        assertThatSigningKeyHasValues(xmlAssert, certificate1(), certificate2());
    }

    @Test
    void changeActiveKey() {
        multipleKeys();
        samlConfig.addAndActivateKey(keyName2(), samlKey2());

        ResponseEntity<String> response = endpoint.metadataEndpoint(request);
        XmlAssert xmlAssert = XmlAssert.assertThat(response.getBody()).withNamespaceContext(xmlNamespaces());

        assertThatEncryptionKeyHasValues(xmlAssert, certificate2());
        assertThatSigningKeyHasValues(xmlAssert, certificate1(), certificate2());
    }

    @Test
    void removeKey() {
        changeActiveKey();
        samlConfig.removeKey(keyName1());

        ResponseEntity<String> response = endpoint.metadataEndpoint(request);
        XmlAssert xmlAssert = XmlAssert.assertThat(response.getBody()).withNamespaceContext(xmlNamespaces());

        assertThatEncryptionKeyHasValues(xmlAssert, certificate2());
        assertThatSigningKeyHasValues(xmlAssert, certificate2());
    }

    private void assertThatSigningKeyHasValues(XmlAssert xmlAssert, String... certificates) {
        assertThatXmlKeysOfTypeHasValues(xmlAssert, "signing", certificates);
    }

    private void assertThatEncryptionKeyHasValues(XmlAssert xmlAssert, String... certificates) {
        assertThatXmlKeysOfTypeHasValues(xmlAssert, "encryption", certificates);
    }

    private void assertThatXmlKeysOfTypeHasValues(XmlAssert xmlAssert, String type, String... certificates) {
        String[] cleanCerts = Arrays.stream(certificates).map(TestCredentialObjects::bare).toArray(String[]::new);
        xmlAssert.hasXPath(KEY_DESCRIPTOR_CERTIFICATE_XPATH_FORMAT.formatted(type))
                .isNotEmpty()
                .extractingText()
                .containsExactlyInAnyOrder(cleanCerts);
    }
}
