package org.cloudfoundry.identity.uaa.provider.saml;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cloudfoundry.identity.uaa.provider.saml.idp.SamlTestUtils;
import org.cloudfoundry.identity.uaa.saml.SamlKey;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.keyinfo.NamedKeyInfoGeneratorManager;
import org.springframework.security.saml.SAMLConstants;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.security.saml.util.SAMLUtil;

import java.security.Security;
import java.util.List;

import static org.cloudfoundry.identity.uaa.provider.saml.SamlKeyManagerFactoryTests.*;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;

@ExtendWith(PollutionPreventionExtension.class)
public class ZoneAwareMetadataGeneratorTests {

    private static final String ZONE_ID = "zone-id";
    private ZoneAwareMetadataGenerator generator;
    private IdentityZone otherZone;
    private IdentityZoneConfiguration otherZoneDefinition;
    private KeyManager keyManager;
    private ExtendedMetadata extendedMetadata;

    public static final SamlKey samlKey1 = new SamlKey(key1, passphrase1, certificate1);
    public static final SamlKey samlKey2 = new SamlKey(key2, passphrase2, certificate2);

    public static final String cert1Plain = certificate1.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "").replace("\n", "");
    public static final String cert2Plain = certificate2.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "").replace("\n", "");

    @BeforeAll
    static void bootstrap() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        DefaultBootstrap.bootstrap();
        NamedKeyInfoGeneratorManager keyInfoGeneratorManager = Configuration.getGlobalSecurityConfiguration().getKeyInfoGeneratorManager();
        keyInfoGeneratorManager.getManager(SAMLConstants.SAML_METADATA_KEY_INFO_GENERATOR);
    }

    @BeforeEach
    void setUp() {
        otherZone = new IdentityZone();
        otherZone.setId(ZONE_ID);
        otherZone.setName(ZONE_ID);
        otherZone.setSubdomain(ZONE_ID);
        otherZone.setConfig(new IdentityZoneConfiguration());
        otherZoneDefinition = otherZone.getConfig();
        otherZoneDefinition.getSamlConfig().setRequestSigned(true);
        otherZoneDefinition.getSamlConfig().setWantAssertionSigned(true);
        otherZoneDefinition.getSamlConfig().addAndActivateKey("key-1", samlKey1);

        otherZone.setConfig(otherZoneDefinition);

        generator = new ZoneAwareMetadataGenerator();
        generator.setEntityBaseURL("http://localhost:8080/uaa");
        generator.setEntityId("entityIdValue");

        extendedMetadata = new org.springframework.security.saml.metadata.ExtendedMetadata();
        extendedMetadata.setIdpDiscoveryEnabled(true);
        extendedMetadata.setAlias("entityAlias");
        extendedMetadata.setSignMetadata(true);
        generator.setExtendedMetadata(extendedMetadata);

        keyManager = new ZoneAwareKeyManager();
        generator.setKeyManager(keyManager);
    }

    @AfterEach
    void tearDown() {
        IdentityZoneHolder.clear();
    }

    @Test
    void testRequestAndWantAssertionSignedInAnotherZone() {
        generator.setRequestSigned(true);
        generator.setWantAssertionSigned(true);
        assertTrue(generator.isRequestSigned());
        assertTrue(generator.isWantAssertionSigned());

        generator.setRequestSigned(false);
        generator.setWantAssertionSigned(false);
        assertFalse(generator.isRequestSigned());
        assertFalse(generator.isWantAssertionSigned());

        IdentityZoneHolder.set(otherZone);

        assertTrue(generator.isRequestSigned());
        assertTrue(generator.isWantAssertionSigned());
    }

    @Test
    void testMetadataContainsSamlBearerGrantEndpoint() throws Exception {
        String metadata = getMetadata(otherZone, keyManager, generator, extendedMetadata);
        assertThat(metadata, containsString("md:AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:URI\" Location=\"http://zone-id.localhost:8080/uaa/oauth/token/alias/zone-id.entityAlias\" index=\"1\"/>"));
    }

    @Test
    void testZonifiedEntityID() {
        generator.setEntityId("local-name");
        assertEquals("local-name", generator.getEntityId());
        assertEquals("local-name", SamlRedirectUtils.getZonifiedEntityId(generator.getEntityId(), IdentityZoneHolder.get()));

        generator.setEntityId(null);
        assertNotNull(generator.getEntityId());
        assertNotNull(SamlRedirectUtils.getZonifiedEntityId(generator.getEntityId(), IdentityZoneHolder.get()));

        IdentityZoneHolder.set(otherZone);

        assertNotNull(generator.getEntityId());
        assertNotNull(SamlRedirectUtils.getZonifiedEntityId(generator.getEntityId(), IdentityZoneHolder.get()));
    }

    @Test
    void testZonifiedValidAndInvalidEntityID() {
        IdentityZone newZone = new IdentityZone();
        newZone.setId("new-zone-id");
        newZone.setName("new-zone-id");
        newZone.setSubdomain("new-zone-id");
        newZone.getConfig().getSamlConfig().setEntityID("local-name");
        IdentityZoneHolder.set(newZone);

        // valid entityID from SamlConfig
        assertEquals("local-name", generator.getEntityId());
        assertEquals("local-name", SamlRedirectUtils.getZonifiedEntityId("local-name", IdentityZoneHolder.get()));
        assertNotNull(generator.getEntityId());

        // remove SamlConfig
        newZone.getConfig().setSamlConfig(null);
        assertNotNull(SamlRedirectUtils.getZonifiedEntityId("local-idp", IdentityZoneHolder.get()));
        // now the entityID is generated id as before this change
        assertEquals("new-zone-id.local-name", SamlRedirectUtils.getZonifiedEntityId("local-name", IdentityZoneHolder.get()));
    }

    @Test
    void defaultKeys() throws Exception {
        String metadata = getMetadata(otherZone, keyManager, generator, extendedMetadata);

        List<String> encryptionKeys = SamlTestUtils.getCertificates(metadata, "encryption");
        assertEquals(1, encryptionKeys.size());
        assertEquals(cert1Plain, encryptionKeys.get(0));

        List<String> signingVerificationCerts = SamlTestUtils.getCertificates(metadata, "signing");
        assertEquals(1, signingVerificationCerts.size());
        assertEquals(cert1Plain, signingVerificationCerts.get(0));
    }

    @Test
    void multipleKeys() throws Exception {
        otherZoneDefinition.getSamlConfig().addKey("key2", samlKey2);
        String metadata = getMetadata(otherZone, keyManager, generator, extendedMetadata);

        List<String> encryptionKeys = SamlTestUtils.getCertificates(metadata, "encryption");
        assertEquals(1, encryptionKeys.size());
        assertEquals(cert1Plain, encryptionKeys.get(0));

        List<String> signingVerificationCerts = SamlTestUtils.getCertificates(metadata, "signing");
        assertEquals(2, signingVerificationCerts.size());
        assertThat(signingVerificationCerts, contains(cert1Plain, cert2Plain));
    }

    @Test
    void changeActiveKey() throws Exception {
        multipleKeys();
        otherZoneDefinition.getSamlConfig().addAndActivateKey("key2", samlKey2);
        String metadata = getMetadata(otherZone, keyManager, generator, extendedMetadata);

        List<String> encryptionKeys = SamlTestUtils.getCertificates(metadata, "encryption");
        assertEquals(1, encryptionKeys.size());
        assertEquals(cert2Plain, encryptionKeys.get(0));

        List<String> signingVerificationCerts = SamlTestUtils.getCertificates(metadata, "signing");
        assertEquals(2, signingVerificationCerts.size());
        assertThat(signingVerificationCerts, contains(cert2Plain, cert1Plain));
    }

    @Test
    void removeKey() throws Exception {
        changeActiveKey();
        otherZoneDefinition.getSamlConfig().removeKey("key-1");
        String metadata = getMetadata(otherZone, keyManager, generator, extendedMetadata);

        List<String> encryptionKeys = SamlTestUtils.getCertificates(metadata, "encryption");
        assertEquals(1, encryptionKeys.size());
        assertEquals(cert2Plain, encryptionKeys.get(0));

        List<String> signingVerificationCerts = SamlTestUtils.getCertificates(metadata, "signing");
        assertEquals(1, signingVerificationCerts.size());
        assertThat(signingVerificationCerts, contains(cert2Plain));
    }

    private static String getMetadata(
            IdentityZone otherZone,
            KeyManager keyManager,
            ZoneAwareMetadataGenerator generator,
            ExtendedMetadata extendedMetadata) throws MarshallingException {
        IdentityZoneHolder.set(otherZone);
        return SAMLUtil.getMetadataAsString(
                mock(MetadataManager.class),
                keyManager,
                generator.generateMetadata(),
                extendedMetadata);
    }

}
