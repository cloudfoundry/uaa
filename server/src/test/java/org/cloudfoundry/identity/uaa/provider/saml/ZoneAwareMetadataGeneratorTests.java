/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.provider.saml;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cloudfoundry.identity.uaa.provider.saml.idp.SamlTestUtils;
import org.cloudfoundry.identity.uaa.saml.SamlKey;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
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

import static org.cloudfoundry.identity.uaa.provider.saml.SamlKeyManagerFactoryTests.certificate1;
import static org.cloudfoundry.identity.uaa.provider.saml.SamlKeyManagerFactoryTests.certificate2;
import static org.cloudfoundry.identity.uaa.provider.saml.SamlKeyManagerFactoryTests.key1;
import static org.cloudfoundry.identity.uaa.provider.saml.SamlKeyManagerFactoryTests.key2;
import static org.cloudfoundry.identity.uaa.provider.saml.SamlKeyManagerFactoryTests.passphrase1;
import static org.cloudfoundry.identity.uaa.provider.saml.SamlKeyManagerFactoryTests.passphrase2;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;

public class ZoneAwareMetadataGeneratorTests {

    public static final String ZONE_ID = "zone-id";
    private ZoneAwareMetadataGenerator generator;
    private IdentityZone otherZone;
    private IdentityZoneConfiguration otherZoneDefinition;
    private KeyManager keyManager;
    private ExtendedMetadata extendedMetadata;

    public static final SamlKey samlKey1 = new SamlKey(key1, passphrase1, certificate1);
    public static final SamlKey samlKey2 = new SamlKey(key2, passphrase2, certificate2);

    public static final String cert1Plain = certificate1.replace("-----BEGIN CERTIFICATE-----","").replace("-----END CERTIFICATE-----","").replace("\n","");
    public static final String cert2Plain = certificate2.replace("-----BEGIN CERTIFICATE-----","").replace("-----END CERTIFICATE-----","").replace("\n","");

    @BeforeClass
    public static void bootstrap() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        DefaultBootstrap.bootstrap();
        NamedKeyInfoGeneratorManager keyInfoGeneratorManager = Configuration.getGlobalSecurityConfiguration().getKeyInfoGeneratorManager();
        keyInfoGeneratorManager.getManager(SAMLConstants.SAML_METADATA_KEY_INFO_GENERATOR);
    }

    @Before
    public void setUp() {
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

    @After
    public void clear() {
        IdentityZoneHolder.clear();
    }

    @Test
    public void test_request_and_want_assertion_signed_in_another_zone() {
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
    public void test_metadata_contains_saml_bearer_grant_endpoint() throws Exception {
        String s = getMetadata();
        assertThat(s, containsString("md:AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:URI\" Location=\"http://zone-id.localhost:8080/uaa/oauth/token/alias/zone-id.entityAlias\" index=\"2\"/>"));
    }

    public String getMetadata() throws MarshallingException {
        IdentityZoneHolder.set(otherZone);
        return SAMLUtil.getMetadataAsString(mock(MetadataManager.class), keyManager , generator.generateMetadata(), extendedMetadata);
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

    public List<String> getCertificates(String metadata, String type) throws Exception {
        return SamlTestUtils.getCertificates(metadata, type);
    }


}
