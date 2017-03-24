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

import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.opensaml.DefaultBootstrap;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.security.saml.util.SAMLUtil;

import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class ZoneAwareMetadataGeneratorTests {

    public static final String ZONE_ID = "zone-id";
    private ZoneAwareMetadataGenerator generator;
    private IdentityZone otherZone;
    private IdentityZoneConfiguration otherZoneDefinition;
    private KeyManager keyManager;
    private ExtendedMetadata extendedMetadata;

    @BeforeClass
    public static void bootstrap() throws Exception {
        DefaultBootstrap.bootstrap();
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

        otherZone.setConfig(otherZoneDefinition);

        generator = new ZoneAwareMetadataGenerator();
        generator.setEntityBaseURL("http://localhost:8080/uaa");
        generator.setEntityId("entityIdValue");
        extendedMetadata = mock(ExtendedMetadata.class);
        when(extendedMetadata.getAlias()).thenReturn("entityAlias");
        generator.setExtendedMetadata(extendedMetadata);

        keyManager = mock(KeyManager.class);
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
        IdentityZoneHolder.set(otherZone);
        String s = SAMLUtil.getMetadataAsString(mock(MetadataManager.class), keyManager , generator.generateMetadata(), extendedMetadata);
        //System.out.println("dom = " + s);
        assertThat(s, containsString("md:AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:URI\" Location=\"http://zone-id.localhost:8080/uaa/oauth/token/alias/zone-id.entityAlias\" index=\"2\"/>"));
    }

    @Test
    public void test_zonified_entityID() {
        generator.setEntityId("local-name");
        assertEquals("local-name", generator.getEntityId());
        assertEquals("local-name", SamlRedirectUtils.getZonifiedEntityId(generator.getEntityId()));

        generator.setEntityId(null);
        assertNotNull(generator.getEntityId());
        assertNotNull(SamlRedirectUtils.getZonifiedEntityId(generator.getEntityId()));

        IdentityZoneHolder.set(otherZone);

        assertNotNull(generator.getEntityId());
        assertNotNull(SamlRedirectUtils.getZonifiedEntityId(generator.getEntityId()));
    }

    @Test
    public void test_zonified_valid_and_invalid_entityID() {
        IdentityZone newZone = new IdentityZone();
        newZone.setId("new-zone-id");
        newZone.setName("new-zone-id");
        newZone.setSubdomain("new-zone-id");
        newZone.getConfig().getSamlConfig().setEntityID("local-name");
        IdentityZoneHolder.set(newZone);

        // valid entityID from SamlConfig
        assertEquals("local-name", generator.getEntityId());
        assertEquals("local-name", SamlRedirectUtils.getZonifiedEntityId("local-name"));
        assertNotNull(generator.getEntityId());

        // remove SamlConfig
        newZone.getConfig().setSamlConfig(null);
        assertNotNull(SamlRedirectUtils.getZonifiedEntityId("local-idp"));
        // now the entityID is generated id as before this change
        assertEquals("new-zone-id.local-name", SamlRedirectUtils.getZonifiedEntityId("local-name"));
    }

}
