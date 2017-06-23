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
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.junit.Before;
import org.junit.Test;
import org.springframework.validation.BindingResult;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class IdentityZoneEndpointsTests {

    IdentityZoneEndpoints endpoints;
    private IdentityZone zone;
    private IdentityZoneProvisioning zoneDao = mock(IdentityZoneProvisioning.class);

    @Before
    public void setup() {
        endpoints = new IdentityZoneEndpoints(
            zoneDao,
            mock(IdentityProviderProvisioning.class),
            mock(IdentityZoneEndpointClientRegistrationService.class),
            mock(ScimGroupProvisioning.class)
        );
        endpoints.setValidator((config, mode) -> config);
    }

    @Test
    public void create_zone() throws Exception {
        zone = createZone();
        when(zoneDao.create(any())).then(invocation -> invocation.getArguments()[0]);
        endpoints.createIdentityZone(zone, mock(BindingResult.class));
    }

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
