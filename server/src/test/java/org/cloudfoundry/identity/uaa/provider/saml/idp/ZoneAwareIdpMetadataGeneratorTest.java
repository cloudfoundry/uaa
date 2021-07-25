package org.cloudfoundry.identity.uaa.provider.saml.idp;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cloudfoundry.identity.uaa.provider.saml.ZoneAwareKeyManager;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.xml.security.keyinfo.NamedKeyInfoGeneratorManager;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.security.saml.util.SAMLUtil;

import java.security.Security;
import java.util.Collections;
import java.util.List;

import static org.cloudfoundry.identity.uaa.provider.saml.ZoneAwareMetadataGeneratorTests.cert1Plain;
import static org.cloudfoundry.identity.uaa.provider.saml.ZoneAwareMetadataGeneratorTests.cert2Plain;
import static org.cloudfoundry.identity.uaa.provider.saml.ZoneAwareMetadataGeneratorTests.samlKey1;
import static org.cloudfoundry.identity.uaa.provider.saml.ZoneAwareMetadataGeneratorTests.samlKey2;
import static org.cloudfoundry.identity.uaa.provider.saml.idp.SamlTestUtils.getCertificates;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasProperty;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.opensaml.common.xml.SAMLConstants.SAML2_ARTIFACT_BINDING_URI;
import static org.opensaml.common.xml.SAMLConstants.SAML2_POST_BINDING_URI;
import static org.opensaml.common.xml.SAMLConstants.SAML2_REDIRECT_BINDING_URI;
import static org.springframework.security.saml.SAMLConstants.SAML_METADATA_KEY_INFO_GENERATOR;

class ZoneAwareIdpMetadataGeneratorTest {

    private String notUaaZoneId;
    private ZoneAwareIdpMetadataGenerator zoneAwareIdpMetadataGenerator;
    private IdentityZone notUaaZone;
    private IdentityZoneConfiguration notUaaZoneConfiguration;
    private KeyManager keyManager;
    private ExtendedMetadata extendedMetadata;

    @BeforeAll
    static void bootstrap() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        DefaultBootstrap.bootstrap();
        NamedKeyInfoGeneratorManager keyInfoGeneratorManager = Configuration.getGlobalSecurityConfiguration().getKeyInfoGeneratorManager();
        keyInfoGeneratorManager.getManager(SAML_METADATA_KEY_INFO_GENERATOR);
    }

    @BeforeEach
    void setup() {
        IdentityZoneHolder.clear();
        notUaaZoneId = "zone-id";
        notUaaZone = new IdentityZone();
        notUaaZone.setId(notUaaZoneId);
        notUaaZone.setName(notUaaZoneId);
        notUaaZone.setSubdomain(notUaaZoneId);
        notUaaZoneConfiguration = new IdentityZoneConfiguration();
        notUaaZoneConfiguration.getSamlConfig().setRequestSigned(true);
        notUaaZoneConfiguration.getSamlConfig().setWantAssertionSigned(true);
        notUaaZoneConfiguration.getSamlConfig().addAndActivateKey("key-1", samlKey1);
        notUaaZone.setConfig(notUaaZoneConfiguration);

        zoneAwareIdpMetadataGenerator = new ZoneAwareIdpMetadataGenerator();

        extendedMetadata = new IdpExtendedMetadata();
        extendedMetadata.setIdpDiscoveryEnabled(true);
        extendedMetadata.setAlias("entityAlias");
        extendedMetadata.setSignMetadata(true);
        zoneAwareIdpMetadataGenerator.setExtendedMetadata((IdpExtendedMetadata) extendedMetadata);
        zoneAwareIdpMetadataGenerator.setEntityBaseURL("http://localhost:8080/uaa");
        keyManager = new ZoneAwareKeyManager();
        zoneAwareIdpMetadataGenerator.setKeyManager(keyManager);
    }

    @AfterEach
    void clear() {
        IdentityZoneHolder.clear();
    }

    @Test
    void canGetMetadata() throws Exception {
        IdentityZoneHolder.set(notUaaZone);
        assertNotNull(SAMLUtil.getMetadataAsString(
                mock(MetadataManager.class),
                keyManager,
                zoneAwareIdpMetadataGenerator.generateMetadata(),
                extendedMetadata));
    }

    @Test
    void defaultKeys() throws Exception {
        IdentityZoneHolder.set(notUaaZone);
        String metadata = SAMLUtil.getMetadataAsString(
                mock(MetadataManager.class),
                keyManager,
                zoneAwareIdpMetadataGenerator.generateMetadata(),
                extendedMetadata);

        List<String> encryptionKeys = getCertificates(metadata, "encryption");
        assertEquals(1, encryptionKeys.size());
        assertEquals(cert1Plain, encryptionKeys.get(0));

        List<String> signingVerificationCerts = getCertificates(metadata, "signing");
        assertEquals(1, signingVerificationCerts.size());
        assertEquals(cert1Plain, signingVerificationCerts.get(0));
    }

    @Test
    void multipleKeys() throws Exception {
        notUaaZoneConfiguration.getSamlConfig().addKey("key2", samlKey2);
        IdentityZoneHolder.set(notUaaZone);
        String metadata = SAMLUtil.getMetadataAsString(
                mock(MetadataManager.class),
                keyManager,
                zoneAwareIdpMetadataGenerator.generateMetadata(),
                extendedMetadata);

        List<String> encryptionKeys = getCertificates(metadata, "encryption");
        assertEquals(1, encryptionKeys.size());
        assertEquals(cert1Plain, encryptionKeys.get(0));

        List<String> signingVerificationCerts = getCertificates(metadata, "signing");
        assertEquals(2, signingVerificationCerts.size());
        assertThat(signingVerificationCerts, contains(cert1Plain, cert2Plain));
    }

    @Test
    void changeActiveKey() throws Exception {
        multipleKeys();
        notUaaZoneConfiguration.getSamlConfig().addAndActivateKey("key2", samlKey2);
        IdentityZoneHolder.set(notUaaZone);
        String metadata = SAMLUtil.getMetadataAsString(
                mock(MetadataManager.class),
                keyManager,
                zoneAwareIdpMetadataGenerator.generateMetadata(),
                extendedMetadata);

        List<String> encryptionKeys = getCertificates(metadata, "encryption");
        assertEquals(1, encryptionKeys.size());
        assertEquals(cert2Plain, encryptionKeys.get(0));

        List<String> signingVerificationCerts = getCertificates(metadata, "signing");
        assertEquals(2, signingVerificationCerts.size());
        assertThat(signingVerificationCerts, contains(cert2Plain, cert1Plain));
    }

    @Test
    void removeKey() throws Exception {
        changeActiveKey();
        notUaaZoneConfiguration.getSamlConfig().removeKey("key-1");
        IdentityZoneHolder.set(notUaaZone);
        String metadata = SAMLUtil.getMetadataAsString(
                mock(MetadataManager.class),
                keyManager,
                zoneAwareIdpMetadataGenerator.generateMetadata(),
                extendedMetadata);

        List<String> encryptionKeys = getCertificates(metadata, "encryption");
        assertEquals(1, encryptionKeys.size());
        assertEquals(cert2Plain, encryptionKeys.get(0));

        List<String> signingVerificationCerts = getCertificates(metadata, "signing");
        assertEquals(1, signingVerificationCerts.size());
        assertThat(signingVerificationCerts, contains(cert2Plain));
    }

    @Test
    void testWantRequestSigned() {
        zoneAwareIdpMetadataGenerator.setWantAuthnRequestSigned(false);
        assertFalse(zoneAwareIdpMetadataGenerator.isWantAuthnRequestSigned());

        zoneAwareIdpMetadataGenerator.setWantAuthnRequestSigned(true);
        assertTrue(zoneAwareIdpMetadataGenerator.isWantAuthnRequestSigned());

        IdentityZoneHolder.set(notUaaZone);

        assertFalse(zoneAwareIdpMetadataGenerator.isWantAuthnRequestSigned());
    }

    @Test
    void artifactBindingNotInSSOList() {
        IdentityZoneHolder.set(notUaaZone);

        IDPSSODescriptor idpSSODescriptor = zoneAwareIdpMetadataGenerator.buildIDPSSODescriptor(
                zoneAwareIdpMetadataGenerator.getEntityBaseURL(),
                zoneAwareIdpMetadataGenerator.getEntityAlias(),
                false,
                Collections.singletonList("email")
        );

        assertThat(idpSSODescriptor.getSingleSignOnServices(), not(hasItem(hasProperty("binding", equalTo(SAML2_ARTIFACT_BINDING_URI)))));
    }

    @Test
    void bindingOrderSSOList() {
        IdentityZoneHolder.set(notUaaZone);
        IDPSSODescriptor idpSSODescriptor = zoneAwareIdpMetadataGenerator.buildIDPSSODescriptor(
                zoneAwareIdpMetadataGenerator.getEntityBaseURL(),
                zoneAwareIdpMetadataGenerator.getEntityAlias(),
                false,
                Collections.singletonList("email")
        );
        assertEquals(SAML2_POST_BINDING_URI, idpSSODescriptor.getSingleSignOnServices().get(0).getBinding());
        assertEquals(SAML2_REDIRECT_BINDING_URI, idpSSODescriptor.getSingleSignOnServices().get(1).getBinding());
    }

    @Test
    void entityIDHonored() {
        IdentityZoneHolder.set(notUaaZone);
        //test default entityID generation within zones
        assertEquals(notUaaZoneId + "." + IdentityZoneHolder.getUaaZone().getConfig().getSamlConfig().getEntityID(), zoneAwareIdpMetadataGenerator.getEntityId());

        notUaaZoneConfiguration.getSamlConfig().setEntityID("randomID");

        assertEquals("randomID", zoneAwareIdpMetadataGenerator.getEntityId());
    }

}
