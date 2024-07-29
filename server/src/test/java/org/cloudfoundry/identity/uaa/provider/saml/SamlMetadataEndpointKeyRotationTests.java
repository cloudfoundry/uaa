package org.cloudfoundry.identity.uaa.provider.saml;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.cloudfoundry.identity.uaa.saml.SamlKey;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.SamlConfig;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManagerImpl;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.xmlunit.assertj.MultipleNodeAssert;
import org.xmlunit.assertj.XmlAssert;

import java.security.Security;
import java.util.Arrays;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.provider.saml.Saml2TestUtils.xmlNamespaces;
import static org.cloudfoundry.identity.uaa.provider.saml.SamlKeyManagerFactoryTests.certificate1;
import static org.cloudfoundry.identity.uaa.provider.saml.SamlKeyManagerFactoryTests.certificate2;
import static org.cloudfoundry.identity.uaa.provider.saml.SamlKeyManagerFactoryTests.key1;
import static org.cloudfoundry.identity.uaa.provider.saml.SamlKeyManagerFactoryTests.key2;
import static org.cloudfoundry.identity.uaa.provider.saml.SamlKeyManagerFactoryTests.legacyCertificate;
import static org.cloudfoundry.identity.uaa.provider.saml.SamlKeyManagerFactoryTests.legacyKey;
import static org.cloudfoundry.identity.uaa.provider.saml.SamlKeyManagerFactoryTests.legacyPassphrase;
import static org.cloudfoundry.identity.uaa.provider.saml.SamlKeyManagerFactoryTests.passphrase1;
import static org.cloudfoundry.identity.uaa.provider.saml.SamlKeyManagerFactoryTests.passphrase2;
import static org.cloudfoundry.identity.uaa.zone.SamlConfig.LEGACY_KEY_ID;
import static org.mockito.Mockito.spy;

public class SamlMetadataEndpointKeyRotationTests {

    private static final String ZONE_ID = "zone-id";
    private static final String REGISTRATION_ID = "regId";
    private static final String ENTITY_ID = "entityIdValue";
    private static final String ENTITY_ALIAS = "entityAlias";
    public static final String KEY_DESCRIPTOR_CERTIFICATE_XPATH_FORMAT = "//md:SPSSODescriptor/md:KeyDescriptor[@use='%s']//ds:X509Certificate";
    private static final String KEY_1 = "key-1";
    private static final String KEY_2 = "key2";

    private static IdentityZoneHolder.Initializer initializer;

    private SamlMetadataEndpoint endpoint;
    private SamlConfig samlConfig;

    private MockHttpServletRequest request;

    private static final SamlKey samlKey1 = new SamlKey(key1, passphrase1, certificate1);
    private static final SamlKey samlKey2 = new SamlKey(key2, passphrase2, certificate2);

    @BeforeAll
    static void beforeAll() {
        Security.addProvider(new BouncyCastleFipsProvider());

        SamlConfigProps samlConfigProps = new SamlConfigProps();
        samlConfigProps.setKeys(Map.of(LEGACY_KEY_ID, new SamlKey(legacyKey, legacyPassphrase, legacyCertificate)));
        samlConfigProps.setActiveKeyId(LEGACY_KEY_ID);
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
        samlConfig.addAndActivateKey(KEY_1, samlKey1);

        IdentityZoneManager identityZoneManager = new IdentityZoneManagerImpl();
        request = new MockHttpServletRequest();

        RelyingPartyRegistrationRepository registrationRepository = new DefaultRelyingPartyRegistrationRepository("entityId", "entityIdAlias");
        RelyingPartyRegistrationResolver registrationResolver = new DefaultRelyingPartyRegistrationResolver(registrationRepository);
        endpoint = spy(new SamlMetadataEndpoint(registrationResolver, identityZoneManager));
        IdentityZoneHolder.set(otherZone);

        request.setRequestURI("http://localhost:8080/uaa");
    }

    @AfterAll
    static void afterAll() {
        IdentityZoneHolder.clear();
        initializer.reset();
    }

    @Test
    @Disabled("SAML test: depends on URI Binding in metadata")
    void metadataContainsSamlBearerGrantEndpoint() {
        ResponseEntity<String> response = endpoint.metadataEndpoint(request, REGISTRATION_ID);
        MultipleNodeAssert acsAssert = XmlAssert.assertThat(response.getBody()).withNamespaceContext(xmlNamespaces()).nodesByXPath("//md:AssertionConsumerService");
        acsAssert.extractingAttribute("Binding").contains("urn:oasis:names:tc:SAML:2.0:bindings:URI");
        acsAssert.extractingAttribute("Location").contains("http://zone-id.localhost:8080/uaa/oauth/token/alias/zone-id.entityAlias");
        acsAssert.extractingAttribute("index").contains("1");
    }

    @Test
    void defaultKeys() {

        ResponseEntity<String> response = endpoint.metadataEndpoint(request, REGISTRATION_ID);
        XmlAssert xmlAssert = XmlAssert.assertThat(response.getBody()).withNamespaceContext(xmlNamespaces());

        assertThatEncryptionKeyHasValues(xmlAssert, certificate1);
        assertThatSigningKeyHasValues(xmlAssert, certificate1);
    }

    @Test
    void multipleKeys() {
        samlConfig.addKey(KEY_2, samlKey2);

        ResponseEntity<String> response = endpoint.metadataEndpoint(request, REGISTRATION_ID);
        XmlAssert xmlAssert = XmlAssert.assertThat(response.getBody()).withNamespaceContext(xmlNamespaces());

        assertThatEncryptionKeyHasValues(xmlAssert, certificate1);
        assertThatSigningKeyHasValues(xmlAssert, certificate1, certificate2);
    }

    @Test
    void changeActiveKey() {
        multipleKeys();
        samlConfig.addAndActivateKey(KEY_2, samlKey2);

        ResponseEntity<String> response = endpoint.metadataEndpoint(request, REGISTRATION_ID);
        XmlAssert xmlAssert = XmlAssert.assertThat(response.getBody()).withNamespaceContext(xmlNamespaces());

        assertThatEncryptionKeyHasValues(xmlAssert, certificate2);
        assertThatSigningKeyHasValues(xmlAssert, certificate1, certificate2);
    }

    @Test
    void removeKey() {
        changeActiveKey();
        samlConfig.removeKey(KEY_1);

        ResponseEntity<String> response = endpoint.metadataEndpoint(request, REGISTRATION_ID);
        XmlAssert xmlAssert = XmlAssert.assertThat(response.getBody()).withNamespaceContext(xmlNamespaces());

        assertThatEncryptionKeyHasValues(xmlAssert, certificate2);
        assertThatSigningKeyHasValues(xmlAssert, certificate2);
    }

    private String clean(String cert) {
        return cert.replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replace("\n", "");
    }

    private void assertThatSigningKeyHasValues(XmlAssert xmlAssert, String... certificates) {
        assertThatXmlKeysOfTypeHasValues(xmlAssert, "signing", certificates);
    }

    private void assertThatEncryptionKeyHasValues(XmlAssert xmlAssert, String... certificates) {
        assertThatXmlKeysOfTypeHasValues(xmlAssert, "encryption", certificates);
    }

    private void assertThatXmlKeysOfTypeHasValues(XmlAssert xmlAssert, String type, String... certificates) {
        String[] cleanCerts = Arrays.stream(certificates).map(this::clean).toArray(String[]::new);
        xmlAssert.hasXPath(KEY_DESCRIPTOR_CERTIFICATE_XPATH_FORMAT.formatted(type))
                .isNotEmpty()
                .extractingText()
                .containsExactlyInAnyOrder(cleanCerts);
    }
}
