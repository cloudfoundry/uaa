/*
 * ****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 * ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.provider.saml;

import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.provider.saml.idp.NonSnarlIdpMetadataManager;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate;
import org.springframework.security.saml.metadata.MetadataMemoryProvider;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class SamlMockMvcTests extends InjectedMockContextTest {

    private NonSnarlMetadataManager spManager;
    private NonSnarlIdpMetadataManager idpManager;
    String entityID;
    private String entityAlias;
    private IdentityZoneProvisioning zoneProvisioning;

    @Before
    public void setup() throws Exception {
        zoneProvisioning = getWebApplicationContext().getBean(IdentityZoneProvisioning.class);
        spManager = getWebApplicationContext().getBean(NonSnarlMetadataManager.class);
        idpManager = getWebApplicationContext().getBean(NonSnarlIdpMetadataManager.class);
        entityID = getWebApplicationContext().getBean("samlEntityID", String.class);
        entityAlias = getWebApplicationContext().getBean("samlSPAlias", String.class);
    }

    @Before
    @After
    public void clear() {
        IdentityZoneHolder.clear();
    }

    @Test
    public void sp_initialized_in_non_snarl_metadata_manager() throws Exception {
        ExtendedMetadataDelegate localServiceProvider = spManager.getLocalServiceProvider();
        assertNotNull(localServiceProvider);
        MetadataProvider provider = localServiceProvider.getDelegate();
        assertNotNull(provider);
        assertTrue(provider instanceof MetadataMemoryProvider);
        String providerSpAlias = spManager.getProviderSpAlias(localServiceProvider);
        assertEquals(entityAlias, providerSpAlias);
        assertEquals(entityID, spManager.getEntityIdForAlias(providerSpAlias));
    }

    @Test
    public void sp_initialization_in_non_snarl_metadata_manager() throws Exception {
        String subdomain = new RandomValueStringGenerator().generate().toLowerCase();
        IdentityZone zone = new IdentityZone()
            .setConfig(new IdentityZoneConfiguration())
            .setSubdomain(subdomain)
            .setId(subdomain)
            .setName(subdomain);
        zone = zoneProvisioning.create(zone);
        IdentityZoneHolder.set(zone);
        ExtendedMetadataDelegate localServiceProvider = spManager.getLocalServiceProvider();
        assertNotNull(localServiceProvider);
        MetadataProvider provider = localServiceProvider.getDelegate();
        assertNotNull(provider);
        assertTrue(provider instanceof MetadataMemoryProvider);
        String providerSpAlias = spManager.getProviderSpAlias(localServiceProvider);
        assertEquals(subdomain + "." + entityAlias, providerSpAlias);
        assertEquals(addSubdomainToEntityId(entityID, subdomain), spManager.getEntityIdForAlias(providerSpAlias));
    }

    public String addSubdomainToEntityId(String entityId, String subdomain) {
        if (UaaUrlUtils.isUrl(entityId)) {
            return UaaUrlUtils.addSubdomainToUrl(entityId, subdomain);
        } else {
            return subdomain + "." + entityId;
        }
    }

}
