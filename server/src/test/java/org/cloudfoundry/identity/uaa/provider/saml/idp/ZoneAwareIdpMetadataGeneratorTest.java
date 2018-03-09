package org.cloudfoundry.identity.uaa.provider.saml.idp;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cloudfoundry.identity.uaa.provider.saml.ZoneAwareKeyManager;
import org.cloudfoundry.identity.uaa.provider.saml.ZoneAwareSamlSecurityConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.SamlConfig;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.keyinfo.NamedKeyInfoGeneratorManager;
import org.opensaml.xml.signature.SignatureConstants;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.security.saml.util.SAMLUtil;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import java.security.Security;
import java.util.Arrays;
import java.util.List;

import static org.cloudfoundry.identity.uaa.provider.saml.ZoneAwareMetadataGeneratorTests.cert1Plain;
import static org.cloudfoundry.identity.uaa.provider.saml.ZoneAwareMetadataGeneratorTests.cert2Plain;
import static org.cloudfoundry.identity.uaa.provider.saml.ZoneAwareMetadataGeneratorTests.samlKey1;
import static org.cloudfoundry.identity.uaa.provider.saml.ZoneAwareMetadataGeneratorTests.samlKey2;
import static org.cloudfoundry.identity.uaa.provider.saml.idp.SamlTestUtils.evaluateXPathExpression;
import static org.cloudfoundry.identity.uaa.provider.saml.idp.SamlTestUtils.getCertificates;
import static org.cloudfoundry.identity.uaa.provider.saml.idp.SamlTestUtils.getMetadataDoc;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasProperty;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.opensaml.common.xml.SAMLConstants.SAML2_ARTIFACT_BINDING_URI;
import static org.opensaml.common.xml.SAMLConstants.SAML2_POST_BINDING_URI;
import static org.opensaml.common.xml.SAMLConstants.SAML2_REDIRECT_BINDING_URI;
import static org.springframework.security.saml.SAMLConstants.SAML_METADATA_KEY_INFO_GENERATOR;

public class ZoneAwareIdpMetadataGeneratorTest {

    public static final String ZONE_ID = "zone-id";
    public static final String ENTITY_ID = "randomID";
    private ZoneAwareIdpMetadataGenerator generator;
    private IdentityZone otherZone;
    private IdentityZoneConfiguration otherZoneDefinition;
    private KeyManager keyManager;
    private ExtendedMetadata extendedMetadata;
    private ZoneAwareSamlSecurityConfiguration securityConfiguration;

    @BeforeClass
    public static void bootstrap() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        DefaultBootstrap.bootstrap();
        NamedKeyInfoGeneratorManager keyInfoGeneratorManager = Configuration.getGlobalSecurityConfiguration().getKeyInfoGeneratorManager();
        keyInfoGeneratorManager.getManager(SAML_METADATA_KEY_INFO_GENERATOR);
    }

    @Before
    public void setup() {
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

        generator = new ZoneAwareIdpMetadataGenerator();

        extendedMetadata = new IdpExtendedMetadata();
        extendedMetadata.setIdpDiscoveryEnabled(true);
        extendedMetadata.setAlias("entityAlias");
        extendedMetadata.setSignMetadata(true);

        securityConfiguration = new ZoneAwareSamlSecurityConfiguration();
        securityConfiguration.setDefaultSignatureAlgorithm(SamlConfig.SignatureAlgorithm.SHA256);

        generator.setExtendedMetadata((IdpExtendedMetadata) extendedMetadata);
        generator.setEntityBaseURL("http://localhost:8080/uaa");
        keyManager = new ZoneAwareKeyManager();
        generator.setKeyManager(keyManager);
        generator.setSecurityConfiguration(securityConfiguration);
    }

    @After
    public void clear() {
        IdentityZoneHolder.clear();
    }

    @Test
    public void can_get_metadata() throws Exception {
        assertNotNull(getMetadata());
    }

    public String getMetadata() throws MarshallingException {
        IdentityZoneHolder.set(otherZone);
        return SAMLUtil.getMetadataAsString(mock(MetadataManager.class), keyManager , generator.generateMetadata(), generator.generateExtendedMetadata());
    }

    @Test
    public void test_metadata_signed_zonified_defaults_to_sha256() throws Exception {
        extendedMetadata.setLocal(true);
        String s = getMetadata();
        Document metadataDoc = getMetadataDoc(s);

        NodeList signatureNodes = evaluateXPathExpression(metadataDoc,
                "//*[local-name()='SignatureMethod' and @*[local-name() = 'Algorithm']='" + SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256+ "']");

        assertEquals(1, signatureNodes.getLength());
    }

    @Test
    public void test_metadata_signed_zonified() throws Exception {
        extendedMetadata.setLocal(true);
        otherZoneDefinition.getSamlConfig().setSignatureAlgorithm(SamlConfig.SignatureAlgorithm.SHA512);
        String s = getMetadata();
        Document metadataDoc = getMetadataDoc(s);

        NodeList signatureNodes = evaluateXPathExpression(metadataDoc,
                "//*[local-name()='SignatureMethod' and @*[local-name() = 'Algorithm']='" + SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA512+ "']");

        assertEquals(1, signatureNodes.getLength());
    }

    @Test
    public void test_extended_metadata_alg_default() {
        ExtendedMetadata metadata = generator.generateExtendedMetadata();
        assertEquals(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256, metadata.getSigningAlgorithm());
    }

    @Test
    public void test_extended_metadata_zonified() {
        otherZoneDefinition.getSamlConfig().setSignatureAlgorithm(SamlConfig.SignatureAlgorithm.SHA512);

        IdentityZoneHolder.set(otherZone);

        ExtendedMetadata metadata = generator.generateExtendedMetadata();
        assertEquals(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA512, metadata.getSigningAlgorithm());
    }

    @Test
    public void default_keys() throws Exception {
        String s = getMetadata();

        List<String> encryptionKeys = getCertificates(s, "encryption");
        assertEquals(1, encryptionKeys.size());
        assertEquals(cert1Plain, encryptionKeys.get(0));

        List<String> signingVerificationCerts = getCertificates(s, "signing");
        assertEquals(1, signingVerificationCerts.size());
        assertEquals(cert1Plain, signingVerificationCerts.get(0));
    }

    @Test
    public void multiple_keys() throws Exception {
        otherZoneDefinition.getSamlConfig().addKey("key2", samlKey2);
        String s = getMetadata();

        List<String> encryptionKeys = getCertificates(s, "encryption");
        assertEquals(1, encryptionKeys.size());
        assertEquals(cert1Plain, encryptionKeys.get(0));

        List<String> signingVerificationCerts = getCertificates(s, "signing");
        assertEquals(2, signingVerificationCerts.size());
        assertThat(signingVerificationCerts, contains(cert1Plain, cert2Plain));
    }

    @Test
    public void change_active_key() throws Exception {
        multiple_keys();
        otherZoneDefinition.getSamlConfig().addAndActivateKey("key2", samlKey2);
        String s = getMetadata();

        List<String> encryptionKeys = getCertificates(s, "encryption");
        assertEquals(1, encryptionKeys.size());
        assertEquals(cert2Plain, encryptionKeys.get(0));

        List<String> signingVerificationCerts = getCertificates(s, "signing");
        assertEquals(2, signingVerificationCerts.size());
        assertThat(signingVerificationCerts, contains(cert2Plain, cert1Plain));
    }

    @Test
    public void remove_key() throws Exception {
        change_active_key();
        otherZoneDefinition.getSamlConfig().removeKey("key-1");
        String s = getMetadata();

        List<String> encryptionKeys = getCertificates(s, "encryption");
        assertEquals(1, encryptionKeys.size());
        assertEquals(cert2Plain, encryptionKeys.get(0));

        List<String> signingVerificationCerts = getCertificates(s, "signing");
        assertEquals(1, signingVerificationCerts.size());
        assertThat(signingVerificationCerts, contains(cert2Plain));
    }

    @Test
    public void testWantRequestSigned() {
        generator.setWantAuthnRequestSigned(false);
        assertFalse(generator.isWantAuthnRequestSigned());

        generator.setWantAuthnRequestSigned(true);
        assertTrue(generator.isWantAuthnRequestSigned());

        IdentityZoneHolder.set(otherZone);

        assertFalse(generator.isWantAuthnRequestSigned());
    }

    @Test
    public void artifactBindingNotInSSOList() throws Exception {
        IdentityZoneHolder.set(otherZone);

        IDPSSODescriptor idpSSODescriptor = generator.buildIDPSSODescriptor(
                                generator.getEntityBaseURL(),
                                generator.getEntityAlias(),
                                false,
                                Arrays.asList("email")
                                );

        assertThat(idpSSODescriptor.getSingleSignOnServices(), not(hasItem(hasProperty("binding", equalTo(SAML2_ARTIFACT_BINDING_URI)))));
    }

    @Test
    public void bindingOrderSSOList() {
        IdentityZoneHolder.set(otherZone);
        IDPSSODescriptor idpSSODescriptor = generator.buildIDPSSODescriptor(
            generator.getEntityBaseURL(),
            generator.getEntityAlias(),
            false,
            Arrays.asList("email")
        );
        assertEquals(SAML2_POST_BINDING_URI, idpSSODescriptor.getSingleSignOnServices().get(0).getBinding());;
        assertEquals(SAML2_REDIRECT_BINDING_URI, idpSSODescriptor.getSingleSignOnServices().get(1).getBinding());;
    }


    @Test
    public void entityIDHonored() {
        IdentityZoneHolder.set(otherZone);
        //test default entityID generation within zones
        assertEquals(ZONE_ID + "." + IdentityZoneHolder.getUaaZone().getConfig().getSamlConfig().getEntityID(), generator.getEntityId());

        otherZoneDefinition.getSamlConfig().setEntityID(ENTITY_ID);

        assertEquals(ENTITY_ID, generator.getEntityId());
    }
}
