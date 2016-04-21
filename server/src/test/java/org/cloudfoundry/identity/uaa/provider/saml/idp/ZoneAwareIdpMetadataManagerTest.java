package org.cloudfoundry.identity.uaa.provider.saml.idp;

import static org.cloudfoundry.identity.uaa.provider.saml.idp.SamlTestUtils.mockSamlServiceProvider;
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
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate;

public class ZoneAwareIdpMetadataManagerTest {

    private final SamlTestUtils samlTestUtils = new SamlTestUtils();
    private SamlServiceProviderConfigurator configurator;
    private ZoneAwareIdpMetadataManager metadataManager;
    SamlServiceProviderProvisioning providerDao;
    IdentityZoneProvisioning zoneDao;
    KeyManager keyManager;

    @Before
    public void setup() throws Exception {
        samlTestUtils.initalize();
        configurator = new SamlServiceProviderConfigurator();
        configurator.setParserPool(new BasicParserPool());
        providerDao = mock(SamlServiceProviderProvisioning.class);
        zoneDao = mock(IdentityZoneProvisioning.class);
        metadataManager = new ZoneAwareIdpMetadataManager(providerDao, zoneDao, configurator, keyManager);
    }

    @Test
    public void testRefreshAllProviders() throws Exception {
        configurator.addSamlServiceProvider(mockSamlServiceProvider());
        when(providerDao.retrieveAll(false, IdentityZone.getUaa().getId()))
                .thenReturn(Arrays.asList(new SamlServiceProvider[] { mockSamlServiceProvider() }));
        when(zoneDao.retrieveAll()).thenReturn(Arrays.asList(new IdentityZone[] { IdentityZone.getUaa() }));
        this.metadataManager.refreshAllProviders();

        assertEquals(1, configurator.getSamlServiceProvidersForZone(IdentityZoneHolder.get()).size());
        assertEquals(1, this.metadataManager.getManager(IdentityZoneHolder.get()).getAvailableProviders().size());

        SamlServiceProvider confProvider = configurator.getSamlServiceProvidersForZone(IdentityZoneHolder.get()).get(0)
                .getSamlServiceProvider();
        ExtendedMetadataDelegate metadataProvider = this.metadataManager.getManager(IdentityZoneHolder.get())
                .getAvailableProviders().get(0);
        metadataProvider.initialize();
        EntityDescriptor entity = metadataProvider.getEntityDescriptor(confProvider.getEntityId());
        assertNotNull(entity);
        assertEquals(confProvider.getEntityId(), entity.getEntityID());
    }

    @Test
    public void testRefreshAllProvidersRemovesNonPersistedProvidersInConfigurator() throws Exception {
        configurator.addSamlServiceProvider(mockSamlServiceProvider());
        configurator.addSamlServiceProvider(mockSamlServiceProvider("non-persisted-saml-sp"));
        when(providerDao.retrieveAll(false, IdentityZone.getUaa().getId()))
                .thenReturn(Arrays.asList(new SamlServiceProvider[] { mockSamlServiceProvider() }));
        when(zoneDao.retrieveAll()).thenReturn(Arrays.asList(new IdentityZone[] { IdentityZone.getUaa() }));
        this.metadataManager.refreshAllProviders();

        assertEquals(1, configurator.getSamlServiceProvidersForZone(IdentityZoneHolder.get()).size());
        assertEquals(1, this.metadataManager.getManager(IdentityZoneHolder.get()).getAvailableProviders().size());

        SamlServiceProvider confProvider = configurator.getSamlServiceProvidersForZone(IdentityZoneHolder.get()).get(0)
                .getSamlServiceProvider();
        ExtendedMetadataDelegate metadataProvider = this.metadataManager.getManager(IdentityZoneHolder.get())
                .getAvailableProviders().get(0);
        metadataProvider.initialize();
        EntityDescriptor entity = metadataProvider.getEntityDescriptor(confProvider.getEntityId());
        assertNotNull(entity);
        assertEquals(confProvider.getEntityId(), entity.getEntityID());
    }

    @Test
    public void testRefreshAllProvidersRemovesInactiveProvidersInConfigurator() throws Exception {
        configurator.addSamlServiceProvider(mockSamlServiceProvider());
        when(providerDao.retrieveAll(false, IdentityZone.getUaa().getId()))
                .thenReturn(Arrays.asList(new SamlServiceProvider[] { mockSamlServiceProvider().setActive(false) }));
        when(zoneDao.retrieveAll()).thenReturn(Arrays.asList(new IdentityZone[] { IdentityZone.getUaa() }));
        this.metadataManager.refreshAllProviders();

        assertEquals(0, configurator.getSamlServiceProvidersForZone(IdentityZoneHolder.get()).size());
        assertEquals(0, this.metadataManager.getManager(IdentityZoneHolder.get()).getAvailableProviders().size());
    }
}
