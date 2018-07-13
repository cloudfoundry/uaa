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

import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.URISyntaxException;
import java.time.Clock;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import org.cloudfoundry.identity.uaa.impl.config.RestTemplateConfig;
import org.cloudfoundry.identity.uaa.provider.SlowHttpServer;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.stubbing.Answer;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.saml.SamlMetadataException;
import org.springframework.security.saml.provider.identity.IdentityProviderService;
import org.springframework.security.saml.provider.identity.config.ExternalServiceProviderConfiguration;
import org.springframework.security.saml.provider.provisioning.HostBasedSamlIdentityProviderProvisioning;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;
import org.springframework.security.saml.spi.DefaultMetadataCache;
import org.springframework.security.saml.spi.DefaultSamlTransformer;
import org.springframework.security.saml.spi.SpringSecuritySaml;
import org.springframework.security.saml.spi.opensaml.OpenSamlImplementation;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestOperations;

import static org.cloudfoundry.identity.uaa.provider.saml.idp.SamlTestUtils.MOCK_SP_ENTITY_ID;
import static org.cloudfoundry.identity.uaa.provider.saml.idp.SamlTestUtils.mockSamlServiceProvider;
import static org.cloudfoundry.identity.uaa.provider.saml.idp.SamlTestUtils.mockSamlServiceProviderForZone;
import static org.cloudfoundry.identity.uaa.provider.saml.idp.SamlTestUtils.mockSamlServiceProviderForZoneWithoutSPSSOInMetadata;
import static org.cloudfoundry.identity.uaa.provider.saml.idp.SamlTestUtils.mockSamlServiceProviderMetadatauriForZone;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;


public class SamlServiceProviderConfiguratorTest {

    private static SpringSecuritySaml implementation;
    private RestOperations mockNetwork;

    @BeforeClass
    public static void initializeOpenSAML() throws Exception {
        implementation = new OpenSamlImplementation(Clock.systemUTC()).init();
    }

    private final SamlTestUtils samlTestUtils = new SamlTestUtils();

    private SamlServiceProviderConfigurator conf = null;

    private SamlServiceProviderProvisioning providerProvisioning;


    @Rule
    public ExpectedException expectedEx = ExpectedException.none();
    private SlowHttpServer slowHttpServer;

    @Before
    public void setup() throws Exception {
        samlTestUtils.initialize();
        conf = new SamlServiceProviderConfigurator();
        DefaultSamlTransformer samlTransformer = new DefaultSamlTransformer(implementation);
        mockNetwork = mock(RestOperations.class);
        DefaultMetadataCache cache = new DefaultMetadataCache(Clock.systemUTC(), mockNetwork, mockNetwork);
        HostBasedSamlIdentityProviderProvisioning resolver = mock(HostBasedSamlIdentityProviderProvisioning.class);
        conf.setResolver(resolver);
        IdentityProviderService identityProviderService = mock(IdentityProviderService.class);
        when(resolver.getHostedProvider()).thenReturn(identityProviderService);

        when(identityProviderService.getRemoteProvider(any(ExternalServiceProviderConfiguration.class)))
            .then(
                (Answer<ServiceProviderMetadata>) invocation -> {
                    Object[] arguments = invocation.getArguments();
                    ExternalServiceProviderConfiguration config = (ExternalServiceProviderConfiguration)arguments[0];
                    String metadata;
                    if (isUri(config.getMetadata())) {
                        metadata = new String(cache.getMetadata(config.getMetadata(), true));
                    } else {
                        metadata = config.getMetadata();
                    }
                    return (ServiceProviderMetadata) samlTransformer.fromXml(metadata.getBytes(), null, null);
                }
            );

        providerProvisioning = mock(SamlServiceProviderProvisioning.class);
        conf.setProviderProvisioning(providerProvisioning);
    }

    @After
    public void cleanupTestMethod() {
        expectedEx = ExpectedException.none();
    }

    /*@Test
    public void testAddAndUpdateAndRemoveSamlServiceProvider() throws Exception {
        SamlServiceProvider sp = mockSamlServiceProviderForZone("uaa");
        SamlServiceProvider spNoHeader = mockSamlServiceProviderWithoutXmlHeaderInMetadata();

        conf.validateSamlServiceProvider(sp);
        assertEquals(1, conf.getSamlServiceProviders().size());
        conf.validateSamlServiceProvider(spNoHeader);
        assertEquals(1, conf.getSamlServiceProviders().size());
    }*/

    @Test
    public void testValidateSamlServiceProviderWithNoNameIDFormats() throws Exception {
        SamlServiceProvider sp = mockSamlServiceProvider("uaa", "");
        try {
            conf.validateSamlServiceProvider(sp);
            Assert.assertTrue("Valid Saml Service Provider", true);
        } catch (Exception e) {
            Assert.fail("Invalid Saml Service Provider");
        }
    }

    @Test
    public void testValidateSamlServiceProviderWithUnsupportedNameIDFormats() throws Exception {
        String entityId = "uaa";
        expectedEx.expect(RuntimeException.class);
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
            IdentityZoneHolder.set(new IdentityZone().setId(zoneId));
            conf.validateSamlServiceProvider(sp);
            when(providerProvisioning.retrieveActive(zoneId)).thenReturn(Arrays.asList(sp));

            String unwantedZoneId = UUID.randomUUID().toString();
            SamlServiceProvider unwantedSp = mockSamlServiceProviderForZone("uaa");
            unwantedSp.setIdentityZoneId(unwantedZoneId);
            IdentityZoneHolder.set(new IdentityZone().setId(unwantedZoneId));
            conf.validateSamlServiceProvider(unwantedSp);
            when(providerProvisioning.retrieveActive(unwantedZoneId)).thenReturn(Arrays.asList(unwantedSp));

            IdentityZone zone = new IdentityZone().setId(zoneId);

            List<SamlServiceProviderHolder> spList = conf.getSamlServiceProvidersForZone(zone);
            assertEquals(1, spList.size());
            assertEquals(sp, spList.get(0).getSamlServiceProvider());
        } finally {
            IdentityZoneHolder.set(IdentityZone.getUaa());
        }
    }

    @Test(expected = RuntimeException.class)
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
    public void testGetEntityId() {
        conf.validateSamlServiceProvider(mockSamlServiceProviderForZone("uaa"));
        for (SamlServiceProviderHolder holder : conf.getSamlServiceProviders()) {
            SamlServiceProvider provider = holder.getSamlServiceProvider();
            switch (provider.getEntityId()) {
                case "cloudfoundry-saml-login": {
                    String entityId = conf.getExtendedMetadataDelegate(provider).getEntityId();
                    assertEquals("cloudfoundry-saml-login", entityId);
                    break;
                }
                default:
                    fail(String.format("Unknown provider %s", provider.getEntityId()));
            }
        }
    }

    @Before
    public void init() {
        slowHttpServer = new SlowHttpServer();
        ticker = mock(TimeService.class);
        when(ticker.getCurrentTimeMillis()).thenAnswer(e -> System.currentTimeMillis());
        RestTemplateConfig restTemplateConfig = new RestTemplateConfig();
        restTemplateConfig.timeout = 120;
    }

    @After
    public void tearDown() {
        slowHttpServer.stop();
    }
    public static final int EXPIRING_TIME_MILLIS = 10 * 60 * 1000;
    private TimeService ticker;

    @Test
    public void testGetExtendedMetadataDelegateUrl() throws Exception {
        slowHttpServer.run();
        expectedEx.expect(SamlMetadataException.class);
        when(mockNetwork.getForObject(anyString(), any())).thenThrow(
            new ResourceAccessException("Simulating a timeout", new SocketTimeoutException("mock"))
        );
        SamlServiceProvider provider = mockSamlServiceProviderMetadatauriForZone("https://localhost:" + SlowHttpServer.PORT);
        conf.getExtendedMetadataDelegate(provider);
    }

    @Test
    public void testNullSSODescriptor() throws Exception {
        conf.validateSamlServiceProvider(mockSamlServiceProviderForZoneWithoutSPSSOInMetadata("uaa"));
    }

    private static boolean isUri(String uri) {
        boolean isUri = false;
        try {
            new URI(uri);
            isUri = true;
        } catch (URISyntaxException e) {
        }
        return isUri;
    }
}
