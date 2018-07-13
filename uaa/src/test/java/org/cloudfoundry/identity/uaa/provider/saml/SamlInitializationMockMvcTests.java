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
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.saml.provider.config.ThreadLocalSamlConfigurationRepository;
import org.springframework.security.saml.provider.provisioning.HostBasedSamlServiceProviderProvisioning;
import org.springframework.security.saml.provider.provisioning.SamlProviderProvisioning;
import org.springframework.security.saml.provider.service.ServiceProviderService;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class SamlInitializationMockMvcTests extends InjectedMockContextTest {

    String entityID;
    private String entityAlias;
    private IdentityZoneProvisioning zoneProvisioning;
    private SamlProviderProvisioning<ServiceProviderService> resolver;

    @Before
    public void setup() throws Exception {
        zoneProvisioning = getWebApplicationContext().getBean(IdentityZoneProvisioning.class);
        entityID = getWebApplicationContext().getBean("samlEntityID", String.class);
        entityAlias = getWebApplicationContext().getBean("samlSPAlias", String.class);
        resolver = getWebApplicationContext().getBean(
            "samlServiceProviderProvisioning",
            HostBasedSamlServiceProviderProvisioning.class
        );
    }

    @Before
    @After
    public void clear() throws Exception {
        IdentityZoneHolder.clear();
        getWebApplicationContext().getBeansOfType(ThreadLocalSamlConfigurationRepository.class)
            .entrySet()
            .stream()
            .forEach(e -> e.getValue().reset());
    }

    @Test
    public void sp_initialized_in_non_snarl_metadata_manager() throws Exception {
        ServiceProviderMetadata localServiceProvider = resolver.getHostedProvider().getMetadata();
        assertNotNull(localServiceProvider);
        String providerSpAlias = localServiceProvider.getEntityAlias();
        assertEquals(entityAlias, providerSpAlias);
        assertEquals(entityID, localServiceProvider.getEntityId());
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
        ServiceProviderMetadata localServiceProvider = resolver.getHostedProvider().getMetadata();
        assertNotNull(localServiceProvider);
        String providerSpAlias = localServiceProvider.getEntityAlias();
        assertEquals(subdomain + "." + entityAlias, providerSpAlias);
        assertEquals(addSubdomainToEntityId(entityID, subdomain), localServiceProvider.getEntityId());
    }

    public String addSubdomainToEntityId(String entityId, String subdomain) {
        if (UaaUrlUtils.isUrl(entityId)) {
            return UaaUrlUtils.addSubdomainToUrl(entityId, subdomain);
        } else {
            return subdomain + "." + entityId;
        }
    }

}
