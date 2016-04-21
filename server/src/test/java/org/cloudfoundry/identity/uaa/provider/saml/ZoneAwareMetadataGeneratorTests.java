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
import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class ZoneAwareMetadataGeneratorTests {

    public static final String ZONE_ID = "zone-id";
    private ZoneAwareMetadataGenerator generator;
    private IdentityZone otherZone;
    private IdentityZoneConfiguration otherZoneDefinition;

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
}
