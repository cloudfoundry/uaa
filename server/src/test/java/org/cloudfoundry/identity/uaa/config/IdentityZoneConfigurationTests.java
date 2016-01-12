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

package org.cloudfoundry.identity.uaa.config;

import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class IdentityZoneConfigurationTests {

    private IdentityZoneConfiguration definition;
    @Before
    public void configure() {
        definition = new IdentityZoneConfiguration();
    }

    @Test
    public void test_want_assertion_signed_setters() {
        definition.getSamlConfig().setRequestSigned(true);
        assertTrue(definition.getSamlConfig().isRequestSigned());
        definition = JsonUtils.readValue(JsonUtils.writeValueAsString(definition), IdentityZoneConfiguration.class);
        assertTrue(definition.getSamlConfig().isRequestSigned());
        definition.getSamlConfig().setRequestSigned(false);
        assertFalse(definition.getSamlConfig().isRequestSigned());
    }

    @Test
    public void test_request_signed_setters() {
        definition.getSamlConfig().setWantAssertionSigned(true);
        assertTrue(definition.getSamlConfig().isWantAssertionSigned());
        definition = JsonUtils.readValue(JsonUtils.writeValueAsString(definition), IdentityZoneConfiguration.class);
        assertTrue(definition.getSamlConfig().isWantAssertionSigned());
        definition.getSamlConfig().setWantAssertionSigned(false);
        assertFalse(definition.getSamlConfig().isWantAssertionSigned());
    }

    @Test
    public void testDeserialize_Without_SamlConfig() {
        String s = JsonUtils.writeValueAsString(definition);
        s = s.replace(",\"samlConfig\":{\"requestSigned\":false,\"wantAssertionSigned\":false}","");
        definition = JsonUtils.readValue(s, IdentityZoneConfiguration.class);
        assertTrue(definition.getSamlConfig().isRequestSigned());
        assertFalse(definition.getSamlConfig().isWantAssertionSigned());
        definition.getSamlConfig().setWantAssertionSigned(true);
        definition.getSamlConfig().setRequestSigned(true);
        s = JsonUtils.writeValueAsString(definition);
        definition = JsonUtils.readValue(s, IdentityZoneConfiguration.class);
        assertTrue(definition.getSamlConfig().isRequestSigned());
        assertTrue(definition.getSamlConfig().isWantAssertionSigned());
        definition.getSamlConfig().setWantAssertionSigned(false);
        definition.getSamlConfig().setRequestSigned(false);
        s = JsonUtils.writeValueAsString(definition);
        definition = JsonUtils.readValue(s, IdentityZoneConfiguration.class);
        assertFalse(definition.getSamlConfig().isRequestSigned());
        assertFalse(definition.getSamlConfig().isWantAssertionSigned());
    }

}
