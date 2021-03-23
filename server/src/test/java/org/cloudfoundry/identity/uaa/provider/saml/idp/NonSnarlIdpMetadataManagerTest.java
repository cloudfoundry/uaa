package org.cloudfoundry.identity.uaa.provider.saml.idp;

import org.cloudfoundry.identity.uaa.provider.saml.ZoneAwareKeyManager;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
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

@ExtendWith(PollutionPreventionExtension.class)
class NonSnarlIdpMetadataManagerTest {
    private SamlTestUtils samlTestUtils;
    private SamlServiceProviderConfigurator samlServiceProviderConfigurator;
    private NonSnarlIdpMetadataManager nonSnarlIdpMetadataManager;
    private SamlServiceProviderProvisioning mockSamlServiceProviderProvisioning;

    @BeforeEach
    void setUp() throws Exception {
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

    @Test
    void getAvailableProvidersAlwaysGetsLocalIdp() throws Exception {
        samlTestUtils.setupZoneWithSamlConfig(IdentityZoneHolder.get());

        when(mockSamlServiceProviderProvisioning.retrieveActive(IdentityZoneHolder.get().getId())).thenReturn(Collections.emptyList());

        List<ExtendedMetadataDelegate> providers = this.nonSnarlIdpMetadataManager.getAvailableProviders();
        assertEquals(1, providers.size());
        assertNotNull(providers.get(0).getRole(SamlTestUtils.IDP_ENTITY_ID, IDPSSODescriptor.DEFAULT_ELEMENT_NAME));
    }

    @Test
    void getAvailableProvidersForDefaultZone() throws Exception {
        IdentityZone uaaZone = IdentityZoneHolder.getUaaZone();
        samlTestUtils.setupZoneWithSamlConfig(uaaZone);
        IdentityZoneHolder.set(uaaZone);
        when(mockSamlServiceProviderProvisioning.retrieveActive(IdentityZone.getUaaZoneId()))
                .thenReturn(Collections.singletonList(
                        mockSamlServiceProviderForZone(IdentityZone.getUaaZoneId())));

        assertEquals(1, samlServiceProviderConfigurator.getSamlServiceProvidersForZone(uaaZone).size());
        //NonSnarlIdpMetadataManager also returns local idp as entity, needs 2
        assertEquals(2, this.nonSnarlIdpMetadataManager.getAvailableProviders().size());

        SamlServiceProvider confProvider = samlServiceProviderConfigurator.getSamlServiceProvidersForZone(uaaZone).get(0)
                .getSamlServiceProvider();
        ExtendedMetadataDelegate metadataProvider = this.nonSnarlIdpMetadataManager.getAvailableProviders().get(1);
        metadataProvider.initialize();
        EntityDescriptor entity = metadataProvider.getEntityDescriptor(confProvider.getEntityId());
        assertNotNull(entity);
        assertEquals(confProvider.getEntityId(), entity.getEntityID());
    }

    @Test
    void getAvailableProvidersForDefaultAndNonDefaultZone() {
        IdentityZone uaaZone = IdentityZoneHolder.getUaaZone();
        samlTestUtils.setupZoneWithSamlConfig(uaaZone);
        IdentityZone testZone = new IdentityZone();
        testZone.setName("non-default-zone");
        testZone.setId(testZone.getName());
        samlTestUtils.setupZoneWithSamlConfig(testZone);

        when(mockSamlServiceProviderProvisioning.retrieveActive(IdentityZone.getUaaZoneId())).thenReturn(Collections.singletonList(
                mockSamlServiceProviderForZone(IdentityZone.getUaaZoneId())));
        when(mockSamlServiceProviderProvisioning.retrieveActive(testZone.getId())).thenReturn(Collections.singletonList(
                mockSamlServiceProviderForZone(testZone.getId())));
        IdentityZoneHolder.set(uaaZone);
        assertEquals(1, samlServiceProviderConfigurator.getSamlServiceProvidersForZone(uaaZone).size());
        assertEquals(2, this.nonSnarlIdpMetadataManager.getAvailableProviders().size());
        IdentityZoneHolder.set(testZone);
        assertEquals(1, samlServiceProviderConfigurator.getSamlServiceProvidersForZone(testZone).size());
        assertEquals(2, this.nonSnarlIdpMetadataManager.getAvailableProviders().size());
    }

    @Test
    void getAvailableProvidersRemovesNonPersistedProvidersInConfigurator() throws Exception {
        IdentityZone uaaZone = IdentityZoneHolder.getUaaZone();
        samlTestUtils.setupZoneWithSamlConfig(uaaZone);
        IdentityZoneHolder.set(uaaZone);

        samlServiceProviderConfigurator.validateSamlServiceProvider(mockSamlServiceProviderForZone(uaaZone.getId()));
        samlServiceProviderConfigurator.validateSamlServiceProvider(mockSamlServiceProvider("non-persisted-saml-sp"));
        when(mockSamlServiceProviderProvisioning.retrieveActive(IdentityZone.getUaaZoneId()))
                .thenReturn(Collections.singletonList(mockSamlServiceProviderForZone(IdentityZone.getUaaZoneId())));
        assertEquals(1, samlServiceProviderConfigurator.getSamlServiceProvidersForZone(uaaZone).size());
        assertEquals(2, this.nonSnarlIdpMetadataManager.getAvailableProviders().size());

        SamlServiceProvider confProvider = samlServiceProviderConfigurator.getSamlServiceProvidersForZone(uaaZone).get(0)
                .getSamlServiceProvider();
        ExtendedMetadataDelegate metadataProvider = this.nonSnarlIdpMetadataManager.getAvailableProviders().get(1);
        metadataProvider.initialize();
        EntityDescriptor entity = metadataProvider.getEntityDescriptor(confProvider.getEntityId());
        assertNotNull(entity);
        assertEquals(confProvider.getEntityId(), entity.getEntityID());
    }
}
