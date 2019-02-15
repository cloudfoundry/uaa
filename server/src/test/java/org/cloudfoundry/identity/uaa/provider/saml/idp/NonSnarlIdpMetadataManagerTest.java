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
package org.cloudfoundry.identity.uaa.provider.saml.idp;

import org.cloudfoundry.identity.uaa.provider.saml.ZoneAwareKeyManager;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.xml.parse.BasicParserPool;
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate;

import java.util.Collections;
import java.util.List;

import static org.cloudfoundry.identity.uaa.provider.saml.idp.SamlTestUtils.mockSamlServiceProvider;
import static org.cloudfoundry.identity.uaa.provider.saml.idp.SamlTestUtils.mockSamlServiceProviderForZone;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class NonSnarlIdpMetadataManagerTest {
    private SamlTestUtils samlTestUtils;
    private SamlServiceProviderConfigurator samlServiceProviderConfigurator;
    private NonSnarlIdpMetadataManager nonSnarlIdpMetadataManager;
    private SamlServiceProviderProvisioning mockSamlServiceProviderProvisioning;

    @BeforeEach
    void setUp() throws Exception {
        IdentityZoneHolder.clear();
        samlTestUtils = new SamlTestUtils();
        samlTestUtils.initialize();
        IdpMetadataGenerator generator = samlTestUtils.mockIdpMetadataGenerator();

        mockSamlServiceProviderProvisioning = mock(SamlServiceProviderProvisioning.class);

        samlServiceProviderConfigurator = new SamlServiceProviderConfigurator();
        samlServiceProviderConfigurator.setParserPool(new BasicParserPool());
        samlServiceProviderConfigurator.setProviderProvisioning(mockSamlServiceProviderProvisioning);

        nonSnarlIdpMetadataManager = new NonSnarlIdpMetadataManager(samlServiceProviderConfigurator);
        nonSnarlIdpMetadataManager.setGenerator(generator);
        nonSnarlIdpMetadataManager.setKeyManager(new ZoneAwareKeyManager());
    }

    @AfterEach
    void tearDown() {
        IdentityZoneHolder.clear();
    }

    @Test
    void getAvailableProvidersAlwaysGetsLocalIdp() throws Exception {
        IdentityZone defaultZone = samlTestUtils.getUaaZoneWithSamlConfig();
        IdentityZoneHolder.set(defaultZone);

        when(mockSamlServiceProviderProvisioning.retrieveActive(defaultZone.getId())).thenReturn(Collections.emptyList());

        List<ExtendedMetadataDelegate> providers = this.nonSnarlIdpMetadataManager.getAvailableProviders();
        assertEquals(1, providers.size());
        assertNotNull(providers.get(0).getRole(SamlTestUtils.IDP_ENTITY_ID, IDPSSODescriptor.DEFAULT_ELEMENT_NAME));
    }

    @Test
    void getAvailableProvidersForDefaultZone() throws Exception {
        IdentityZone defaultZone = samlTestUtils.getUaaZoneWithSamlConfig();
        IdentityZoneHolder.set(defaultZone);
        when(mockSamlServiceProviderProvisioning.retrieveActive(defaultZone.getId()))
                .thenReturn(Collections.singletonList(
                        mockSamlServiceProviderForZone(defaultZone.getId())));

        assertEquals(1, samlServiceProviderConfigurator.getSamlServiceProvidersForZone(defaultZone).size());
        //NonSnarlIdpMetadataManager also returns local idp as entity, needs 2
        assertEquals(2, this.nonSnarlIdpMetadataManager.getAvailableProviders().size());

        SamlServiceProvider confProvider = samlServiceProviderConfigurator.getSamlServiceProvidersForZone(defaultZone).get(0)
                .getSamlServiceProvider();
        ExtendedMetadataDelegate metadataProvider = this.nonSnarlIdpMetadataManager.getAvailableProviders().get(1);
        metadataProvider.initialize();
        EntityDescriptor entity = metadataProvider.getEntityDescriptor(confProvider.getEntityId());
        assertNotNull(entity);
        assertEquals(confProvider.getEntityId(), entity.getEntityID());
    }

    @Test
    void getAvailableProvidersForDefaultAndNonDefaultZone() {
        IdentityZone defaultZone = samlTestUtils.getUaaZoneWithSamlConfig();
        IdentityZone testZone = new IdentityZone();
        testZone.setName("non-default-zone");
        testZone.setId(testZone.getName());
        samlTestUtils.setupZoneWithSamlConfig(testZone);

        when(mockSamlServiceProviderProvisioning.retrieveActive(defaultZone.getId())).thenReturn(Collections.singletonList(
                mockSamlServiceProviderForZone(defaultZone.getId())));
        when(mockSamlServiceProviderProvisioning.retrieveActive(testZone.getId())).thenReturn(Collections.singletonList(
                mockSamlServiceProviderForZone(testZone.getId())));
        IdentityZoneHolder.set(defaultZone);
        assertEquals(1, samlServiceProviderConfigurator.getSamlServiceProvidersForZone(defaultZone).size());
        assertEquals(2, this.nonSnarlIdpMetadataManager.getAvailableProviders().size());
        IdentityZoneHolder.set(testZone);
        assertEquals(1, samlServiceProviderConfigurator.getSamlServiceProvidersForZone(testZone).size());
        assertEquals(2, this.nonSnarlIdpMetadataManager.getAvailableProviders().size());
    }

    @Test
    void getAvailableProvidersRemovesNonPersistedProvidersInConfigurator() throws Exception {
        IdentityZone defaultZone = samlTestUtils.getUaaZoneWithSamlConfig();
        samlServiceProviderConfigurator.validateSamlServiceProvider(mockSamlServiceProviderForZone(defaultZone.getId()));
        samlServiceProviderConfigurator.validateSamlServiceProvider(mockSamlServiceProvider("non-persisted-saml-sp"));
        when(mockSamlServiceProviderProvisioning.retrieveActive(defaultZone.getId()))
                .thenReturn(Collections.singletonList(mockSamlServiceProviderForZone(defaultZone.getId())));

        IdentityZoneHolder.set(defaultZone);
        assertEquals(1, samlServiceProviderConfigurator.getSamlServiceProvidersForZone(defaultZone).size());
        assertEquals(2, this.nonSnarlIdpMetadataManager.getAvailableProviders().size());

        SamlServiceProvider confProvider = samlServiceProviderConfigurator.getSamlServiceProvidersForZone(defaultZone).get(0)
                .getSamlServiceProvider();
        ExtendedMetadataDelegate metadataProvider = this.nonSnarlIdpMetadataManager.getAvailableProviders().get(1);
        metadataProvider.initialize();
        EntityDescriptor entity = metadataProvider.getEntityDescriptor(confProvider.getEntityId());
        assertNotNull(entity);
        assertEquals(confProvider.getEntityId(), entity.getEntityID());
    }
}
