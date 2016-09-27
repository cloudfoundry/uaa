package org.cloudfoundry.identity.uaa.provider.saml.idp;

import static org.cloudfoundry.identity.uaa.provider.saml.idp.SamlTestUtils.mockSamlServiceProvider;
import static org.cloudfoundry.identity.uaa.provider.saml.idp.SamlTestUtils.mockSamlServiceProviderForZone;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Arrays;

import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.xml.parse.BasicParserPool;
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate;

public class ZoneAwareIdpMetadataManagerTest {

    private final SamlTestUtils samlTestUtils = new SamlTestUtils();
    private SamlServiceProviderConfigurator configurator;
    private ZoneAwareIdpMetadataManager metadataManager;
    SamlServiceProviderProvisioning providerDao;
    IdentityZoneProvisioning zoneDao;

    @Before
    public void setup() throws Exception {
        samlTestUtils.initalize();
        configurator = new SamlServiceProviderConfigurator();
        configurator.setParserPool(new BasicParserPool());
        providerDao = mock(SamlServiceProviderProvisioning.class);
        zoneDao = mock(IdentityZoneProvisioning.class);
        //TODO initialize IdentityZoneHolder with UAA config (keymanager)
        metadataManager = new ZoneAwareIdpMetadataManager(providerDao, zoneDao, configurator);
    }

    @Test
    public void testRefreshProvidersForDefaultZone() throws Exception {
        IdentityZone defaultZone = IdentityZone.getUaa();
        when(providerDao.retrieveAll(false, defaultZone.getId()))
                .thenReturn(Arrays.asList(new SamlServiceProvider[] { mockSamlServiceProviderForZone(defaultZone.getId()) }));
        when(zoneDao.retrieveAll()).thenReturn(Arrays.asList(new IdentityZone[] { defaultZone }));
        this.metadataManager.refreshAllProviders();

        assertEquals(1, configurator.getSamlServiceProvidersForZone(defaultZone).size());
        assertEquals(1, this.metadataManager.getManager(defaultZone).getAvailableProviders().size());

        SamlServiceProvider confProvider = configurator.getSamlServiceProvidersForZone(defaultZone).get(0)
                .getSamlServiceProvider();
        ExtendedMetadataDelegate metadataProvider = this.metadataManager.getManager(defaultZone)
                .getAvailableProviders().get(0);
        metadataProvider.initialize();
        EntityDescriptor entity = metadataProvider.getEntityDescriptor(confProvider.getEntityId());
        assertNotNull(entity);
        assertEquals(confProvider.getEntityId(), entity.getEntityID());
    }

    @Test
    public void testRefreshProvidersForDefaultAndNonDefaultZone() throws Exception {
        IdentityZone defaultZone = IdentityZone.getUaa();
        IdentityZone testZone = new IdentityZone();
        testZone.setName("non-default-zone");
        testZone.setId(testZone.getName());

        when(providerDao.retrieveAll(false, defaultZone.getId())).thenReturn(Arrays.asList(
        		new SamlServiceProvider[] { mockSamlServiceProviderForZone(defaultZone.getId()) }));
        when(providerDao.retrieveAll(false, testZone.getId())).thenReturn(Arrays.asList(
        		new SamlServiceProvider[] { mockSamlServiceProviderForZone(testZone.getId()) }));
        when(zoneDao.retrieveAll()).thenReturn(Arrays.asList(new IdentityZone[] { defaultZone, testZone }));
        this.metadataManager.refreshAllProviders();
        assertEquals(1, configurator.getSamlServiceProvidersForZone(defaultZone).size());
        assertEquals(1, this.metadataManager.getManager(defaultZone).getAvailableProviders().size());
        assertEquals(1, configurator.getSamlServiceProvidersForZone(testZone).size());
        assertEquals(1, this.metadataManager.getManager(testZone).getAvailableProviders().size());
    }

    @Test
    public void testRefreshAllProvidersRemovesNonPersistedProvidersInConfigurator() throws Exception {
        IdentityZone defaultZone = IdentityZone.getUaa();
        configurator.addSamlServiceProvider(mockSamlServiceProviderForZone(defaultZone.getId()));
        configurator.addSamlServiceProvider(mockSamlServiceProvider("non-persisted-saml-sp"));
        when(providerDao.retrieveAll(false, defaultZone.getId()))
                .thenReturn(Arrays.asList(new SamlServiceProvider[] { mockSamlServiceProviderForZone(defaultZone.getId()) }));
        when(zoneDao.retrieveAll()).thenReturn(Arrays.asList(new IdentityZone[] { defaultZone }));
        this.metadataManager.refreshAllProviders();

        assertEquals(1, configurator.getSamlServiceProvidersForZone(defaultZone).size());
        assertEquals(1, this.metadataManager.getManager(defaultZone).getAvailableProviders().size());

        SamlServiceProvider confProvider = configurator.getSamlServiceProvidersForZone(defaultZone).get(0)
                .getSamlServiceProvider();
        ExtendedMetadataDelegate metadataProvider = this.metadataManager.getManager(defaultZone)
                .getAvailableProviders().get(0);
        metadataProvider.initialize();
        EntityDescriptor entity = metadataProvider.getEntityDescriptor(confProvider.getEntityId());
        assertNotNull(entity);
        assertEquals(confProvider.getEntityId(), entity.getEntityID());
    }

    @Test
    public void testRefreshAllProvidersRemovesInactiveProvidersInConfigurator() throws Exception {
        IdentityZone defaultZone = IdentityZone.getUaa();
        configurator.addSamlServiceProvider(mockSamlServiceProviderForZone(defaultZone.getId()));
        when(providerDao.retrieveAll(false, defaultZone.getId()))
                .thenReturn(Arrays.asList(new SamlServiceProvider[] { mockSamlServiceProviderForZone(defaultZone.getId()).setActive(false) }));
        when(zoneDao.retrieveAll()).thenReturn(Arrays.asList(new IdentityZone[] { defaultZone }));
        this.metadataManager.refreshAllProviders();

        assertEquals(0, configurator.getSamlServiceProvidersForZone(defaultZone).size());
        assertEquals(0, this.metadataManager.getManager(defaultZone).getAvailableProviders().size());
    }
}
