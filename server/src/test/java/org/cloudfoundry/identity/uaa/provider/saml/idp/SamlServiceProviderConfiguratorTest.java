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

import org.cloudfoundry.identity.uaa.cache.ExpiringUrlCache;
import org.cloudfoundry.identity.uaa.impl.config.RestTemplateConfig;
import org.cloudfoundry.identity.uaa.provider.SlowHttpServer;
import org.cloudfoundry.identity.uaa.provider.saml.ComparableProvider;
import org.cloudfoundry.identity.uaa.provider.saml.FixedHttpMetaDataProvider;
import org.cloudfoundry.identity.uaa.test.TestUtils;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.parse.BasicParserPool;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

import static org.cloudfoundry.identity.uaa.provider.saml.idp.SamlTestUtils.MOCK_SP_ENTITY_ID;
import static org.cloudfoundry.identity.uaa.provider.saml.idp.SamlTestUtils.mockSamlServiceProvider;
import static org.cloudfoundry.identity.uaa.provider.saml.idp.SamlTestUtils.mockSamlServiceProviderForZone;
import static org.cloudfoundry.identity.uaa.provider.saml.idp.SamlTestUtils.mockSamlServiceProviderForZoneWithoutSPSSOInMetadata;
import static org.cloudfoundry.identity.uaa.provider.saml.idp.SamlTestUtils.mockSamlServiceProviderMetadatauriForZone;
import static org.cloudfoundry.identity.uaa.test.TestUtils.withId;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;


public class SamlServiceProviderConfiguratorTest {

    private final SamlTestUtils samlTestUtils = new SamlTestUtils();
    private SamlServiceProviderConfigurator conf = null;
    private SamlServiceProviderProvisioning providerProvisioning;

    @Rule
    public ExpectedException expectedEx = ExpectedException.none();
    private SlowHttpServer slowHttpServer;

    @Before
    public void setupSamlSpConfAndSlowHttpServer() throws Exception {
        samlTestUtils.initialize();
        conf = new SamlServiceProviderConfigurator();
        providerProvisioning = mock(SamlServiceProviderProvisioning.class);
        conf.setProviderProvisioning(providerProvisioning);
        conf.setParserPool(new BasicParserPool());

        slowHttpServer = new SlowHttpServer();
        TimeService mockTimeService = mock(TimeService.class);
        when(mockTimeService.getCurrentTimeMillis()).thenAnswer(e -> System.currentTimeMillis());
        RestTemplateConfig restTemplateConfig = RestTemplateConfig.createDefaults();
        restTemplateConfig.timeout = 120;
        FixedHttpMetaDataProvider fixedHttpMetaDataProvider = new FixedHttpMetaDataProvider(
                restTemplateConfig.trustingRestTemplate(),
                restTemplateConfig.nonTrustingRestTemplate(),
                new ExpiringUrlCache(Duration.ofMinutes(10), mockTimeService, 2)
        );

        conf.setFixedHttpMetaDataProvider(fixedHttpMetaDataProvider);
    }

    @After
    public void stopSlowHttpServer() {
        slowHttpServer.stop();
    }

    @Test
    public void testValidateSamlServiceProviderWithNoNameIDFormats() {
        SamlServiceProvider sp = mockSamlServiceProvider("uaa", "");
        try {
            conf.validateSamlServiceProvider(sp);
            Assert.assertTrue("Valid Saml Service Provider", true);
        } catch (MetadataProviderException e) {
            Assert.fail("Invalid Saml Service Provider");
        }
    }

    @Test
    public void testValidateSamlServiceProviderWithUnsupportedNameIDFormats() throws Exception {
        String entityId = "uaa";
        expectedEx.expect(MetadataProviderException.class);
        expectedEx.expectMessage("UAA does not support any of the NameIDFormats specified in the metadata for entity: " + entityId);
        SamlServiceProvider sp = mockSamlServiceProvider(entityId, "<md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>");
        conf.validateSamlServiceProvider(sp);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testAddSamlServiceProviderToWrongZone() throws Exception {
        SamlServiceProvider sp = mockSamlServiceProviderForZone("uaa");
        sp.setIdentityZoneId(UUID.randomUUID().toString());
        conf.validateSamlServiceProvider(sp);
    }

    @Test
    public void testGetSamlServiceProvidersForZone() throws Exception {
        try {
            String zoneId = UUID.randomUUID().toString();
            SamlServiceProvider sp = mockSamlServiceProviderForZone("uaa");
            sp.setIdentityZoneId(zoneId);
            IdentityZoneHolder.set(withId(zoneId));
            conf.validateSamlServiceProvider(sp);
            when(providerProvisioning.retrieveActive(zoneId)).thenReturn(Collections.singletonList(sp));

            String unwantedZoneId = UUID.randomUUID().toString();
            SamlServiceProvider unwantedSp = mockSamlServiceProviderForZone("uaa");
            unwantedSp.setIdentityZoneId(unwantedZoneId);
            IdentityZoneHolder.set(withId(unwantedZoneId));
            conf.validateSamlServiceProvider(unwantedSp);
            when(providerProvisioning.retrieveActive(unwantedZoneId)).thenReturn(Collections.singletonList(unwantedSp));

            IdentityZone zone = withId(zoneId);

            List<SamlServiceProviderHolder> spList = conf.getSamlServiceProvidersForZone(zone);
            assertEquals(1, spList.size());
            assertEquals(sp, spList.get(0).getSamlServiceProvider());
        } finally {
            TestUtils.resetIdentityZoneHolder(null);
        }
    }

    @Test(expected = MetadataProviderException.class)
    public void testValidateSamlServiceProviderWithConflictingEntityId() throws Exception {
        SamlServiceProvider sp = mockSamlServiceProviderForZone("uaa");

        conf.validateSamlServiceProvider(sp);
        SamlServiceProviderDefinition duplicateDef = SamlServiceProviderDefinition.Builder.get()
          .setMetaDataLocation(String.format(SamlTestUtils.UNSIGNED_SAML_SP_METADATA_WITHOUT_ID,
            new RandomValueStringGenerator().generate()))
          .setNameID("sample-nameID").setSingleSignOnServiceIndex(1)
          .setMetadataTrustCheck(true).build();
        SamlServiceProvider duplicate = new SamlServiceProvider().setEntityId(MOCK_SP_ENTITY_ID + "_2").setIdentityZoneId("uaa")
          .setConfig(duplicateDef);
        conf.validateSamlServiceProvider(duplicate);
    }

    @Test(expected = NullPointerException.class)
    public void testValidateNullSamlServiceProvider() throws Exception {
        conf.validateSamlServiceProvider(null);
    }

    @Test(expected = NullPointerException.class)
    public void testValidatorSamlServiceProviderWithNullIdentityZoneId() throws Exception {
        SamlServiceProvider sp = mockSamlServiceProviderForZone("uaa");
        sp.setIdentityZoneId(null);
        conf.validateSamlServiceProvider(sp);
    }

    @Test
    public void testGetEntityId() throws Exception {
        conf.validateSamlServiceProvider(mockSamlServiceProviderForZone("uaa"));
        for (SamlServiceProviderHolder holder : conf.getSamlServiceProviders()) {
            SamlServiceProvider provider = holder.getSamlServiceProvider();
            if ("cloudfoundry-saml-login".equals(provider.getEntityId())) {
                ComparableProvider compProvider = (ComparableProvider) conf.getExtendedMetadataDelegate(provider)
                        .getDelegate();
                assertEquals("cloudfoundry-saml-login", compProvider.getEntityID());
            } else {
                fail(String.format("Unknown provider %s", provider.getEntityId()));
            }
        }
    }

    @Test
    public void testGetExtendedMetadataDelegateUrl() throws MetadataProviderException {
        slowHttpServer.run();
        expectedEx.expect(MetadataProviderException.class);
        expectedEx.expectMessage("Unavailable Metadata Provider");

        SamlServiceProvider provider = mockSamlServiceProviderMetadatauriForZone(slowHttpServer.getUrl());

        conf.getExtendedMetadataDelegate(provider);
    }

    @Test
    public void testNullSSODescriptor() throws Exception {
        conf.validateSamlServiceProvider(mockSamlServiceProviderForZoneWithoutSPSSOInMetadata("uaa"));
    }

}
