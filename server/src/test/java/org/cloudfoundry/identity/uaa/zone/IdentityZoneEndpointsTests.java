/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
 *
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.saml.SamlKey;
import org.junit.Test;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.mockito.Mockito.mock;

public class IdentityZoneEndpointsTests {

    IdentityZoneEndpoints endpoints = new IdentityZoneEndpoints(
        mock(IdentityZoneProvisioning.class),
        mock(IdentityProviderProvisioning.class),
        mock(IdentityZoneEndpointClientRegistrationService.class)
    );
    private IdentityZone zone;

    @Test
    public void remove_keys_from_map() {
        zone = createZone();

        endpoints.removeKeys(zone);

        assertNull(zone.getConfig().getSamlConfig().getPrivateKey());
        assertNull(zone.getConfig().getSamlConfig().getPrivateKeyPassword());
        zone.getConfig().getSamlConfig().getKeys().entrySet().forEach(
            entry -> {
                assertNull(entry.getValue().getKey());
                assertNull(entry.getValue().getPassphrase());
            }
        );
    }

    private IdentityZone createZone() {
        IdentityZone zone = MultitenancyFixture.identityZone("id", "subdomain");
        IdentityZoneConfiguration config = zone.getConfig();
        assertNotNull(config);
        zone.getConfig().getSamlConfig().setPrivateKey("private");
        zone.getConfig().getSamlConfig().setPrivateKeyPassword("passphrase");
        zone.getConfig().getSamlConfig().setCertificate("certificate");
        zone.getConfig().getSamlConfig().addAndActivateKey("active", new SamlKey("private1", "passphrase1", "certificate1"));

        assertNotNull(zone.getConfig().getSamlConfig().getPrivateKey());
        assertNotNull(zone.getConfig().getSamlConfig().getPrivateKeyPassword());
        zone.getConfig().getSamlConfig().getKeys().entrySet().forEach(
            entry -> {
                assertNotNull(entry.getValue().getKey());
                assertNotNull(entry.getValue().getPassphrase());
            }
        );
        return zone;
    }

    @Test
    public void restore_keys() {
        remove_keys_from_map();
        IdentityZone original = createZone();
        endpoints.restoreSecretProperties(original, zone);


        assertNotNull(zone.getConfig().getSamlConfig().getPrivateKey());
        assertNotNull(zone.getConfig().getSamlConfig().getPrivateKeyPassword());
        zone.getConfig().getSamlConfig().getKeys().entrySet().forEach(
            entry -> {
                assertNotNull(entry.getValue().getKey());
                assertNotNull(entry.getValue().getPassphrase());
            }
        );

    }
}
