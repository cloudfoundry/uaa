package org.cloudfoundry.identity.uaa.provider.saml.idp;

import org.cloudfoundry.identity.uaa.provider.saml.ZoneAwareKeyManager;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.xml.parse.BasicParserPool;
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate;

import java.util.List;
import java.util.Arrays;
import java.util.Collections;

import static org.cloudfoundry.identity.uaa.provider.saml.idp.SamlTestUtils.mockSamlServiceProvider;
import static org.cloudfoundry.identity.uaa.provider.saml.idp.SamlTestUtils.mockSamlServiceProviderForZone;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 *
 */
public class NonSnarlIdpMetadataManagerTest {
    private final SamlTestUtils samlTestUtils = new SamlTestUtils();
    private SamlServiceProviderConfigurator configurator;
    private IdpMetadataGenerator generator;
    private NonSnarlIdpMetadataManager metadataManager;
    SamlServiceProviderProvisioning providerProvisioning;
    IdentityZoneProvisioning zoneDao;
    
    //TODO add test for getting local uaa idp

    @Before
    public void setup() throws Exception {
        samlTestUtils.initialize();
        configurator = new SamlServiceProviderConfigurator();
        configurator.setParserPool(new BasicParserPool());
        generator = samlTestUtils.mockIdpMetadataGenerator();

        providerProvisioning = mock(SamlServiceProviderProvisioning.class);
        configurator.setProviderProvisioning(providerProvisioning);
        metadataManager = new NonSnarlIdpMetadataManager(configurator);
        metadataManager.setGenerator(generator);
        metadataManager.setKeyManager(new ZoneAwareKeyManager());
    }
    
    @After
    public void teardown() throws Exception {
        IdentityZoneHolder.clear();
    }
    
    @Test
    public void testGetAvailableProvidersAlwaysGetsLocalIdp() throws Exception {
        IdentityZone defaultZone = samlTestUtils.getUaaZoneWithSamlConfig();
        IdentityZoneHolder.set(defaultZone);

        when(providerProvisioning.retrieveActive(defaultZone.getId())).thenReturn(Collections.emptyList());
        
        List<ExtendedMetadataDelegate> providers = this.metadataManager.getAvailableProviders();
        assertEquals(1, providers.size());
        assertNotNull(providers.get(0).getRole(samlTestUtils.IDP_ENTITY_ID, IDPSSODescriptor.DEFAULT_ELEMENT_NAME));

    }

    @Test
    public void testGetAvailableProvidersForDefaultZone() throws Exception {
        IdentityZone defaultZone = samlTestUtils.getUaaZoneWithSamlConfig();
        IdentityZoneHolder.set(defaultZone);
        when(providerProvisioning.retrieveActive(defaultZone.getId()))
                .thenReturn(Arrays.asList(
                        new SamlServiceProvider[] { mockSamlServiceProviderForZone(defaultZone.getId()) }
                        ));

        assertEquals(1, configurator.getSamlServiceProvidersForZone(defaultZone).size());
        //NonSnarlIdpMetadataManager also returns local idp as entity, needs 2
        assertEquals(2, this.metadataManager.getAvailableProviders().size());

        SamlServiceProvider confProvider = configurator.getSamlServiceProvidersForZone(defaultZone).get(0)
                .getSamlServiceProvider();
        ExtendedMetadataDelegate metadataProvider = this.metadataManager.getAvailableProviders().get(1);
        metadataProvider.initialize();
        EntityDescriptor entity = metadataProvider.getEntityDescriptor(confProvider.getEntityId());
        assertNotNull(entity);
        assertEquals(confProvider.getEntityId(), entity.getEntityID());
    }

    @Test
    public void testGetAvailableProvidersForDefaultAndNonDefaultZone() throws Exception {
        IdentityZone defaultZone = samlTestUtils.getUaaZoneWithSamlConfig();
        IdentityZone testZone = new IdentityZone();
        testZone.setName("non-default-zone");
        testZone.setId(testZone.getName());
        samlTestUtils.setupZoneWithSamlConfig(testZone);

        when(providerProvisioning.retrieveActive(defaultZone.getId())).thenReturn(Arrays.asList(
                new SamlServiceProvider[] { mockSamlServiceProviderForZone(defaultZone.getId()) }));
        when(providerProvisioning.retrieveActive(testZone.getId())).thenReturn(Arrays.asList(
                new SamlServiceProvider[] { mockSamlServiceProviderForZone(testZone.getId()) }));
        IdentityZoneHolder.set(defaultZone);
        assertEquals(1, configurator.getSamlServiceProvidersForZone(defaultZone).size());
        assertEquals(2, this.metadataManager.getAvailableProviders().size());
        IdentityZoneHolder.set(testZone);
        assertEquals(1, configurator.getSamlServiceProvidersForZone(testZone).size());
        assertEquals(2, this.metadataManager.getAvailableProviders().size());
    }

    @Test
    public void testGetAvailableProvidersRemovesNonPersistedProvidersInConfigurator() throws Exception {
        IdentityZone defaultZone = samlTestUtils.getUaaZoneWithSamlConfig();
        configurator.validateSamlServiceProvider(mockSamlServiceProviderForZone(defaultZone.getId()));
        configurator.validateSamlServiceProvider(mockSamlServiceProvider("non-persisted-saml-sp"));
        when(providerProvisioning.retrieveActive(defaultZone.getId()))
                .thenReturn(Arrays.asList(new SamlServiceProvider[] { mockSamlServiceProviderForZone(defaultZone.getId()) }));
        
        IdentityZoneHolder.set(defaultZone);
        assertEquals(1, configurator.getSamlServiceProvidersForZone(defaultZone).size());
        assertEquals(2, this.metadataManager.getAvailableProviders().size());

        SamlServiceProvider confProvider = configurator.getSamlServiceProvidersForZone(defaultZone).get(0)
                .getSamlServiceProvider();
        ExtendedMetadataDelegate metadataProvider = this.metadataManager.getAvailableProviders().get(1);
        metadataProvider.initialize();
        EntityDescriptor entity = metadataProvider.getEntityDescriptor(confProvider.getEntityId());
        assertNotNull(entity);
        assertEquals(confProvider.getEntityId(), entity.getEntityID());
    }

}
