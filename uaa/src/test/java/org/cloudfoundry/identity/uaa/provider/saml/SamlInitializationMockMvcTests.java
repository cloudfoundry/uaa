package org.cloudfoundry.identity.uaa.provider.saml;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate;
import org.springframework.security.saml.metadata.MetadataMemoryProvider;
import org.springframework.web.context.WebApplicationContext;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

@DefaultTestContext
class SamlInitializationMockMvcTests {
    private NonSnarlMetadataManager spManager;
    private String entityID;
    private String entityAlias;
    private IdentityZoneProvisioning zoneProvisioning;

    @BeforeEach
    void setUp(@Autowired WebApplicationContext webApplicationContext) {
        zoneProvisioning = webApplicationContext.getBean(IdentityZoneProvisioning.class);
        spManager = webApplicationContext.getBean(NonSnarlMetadataManager.class);
        entityID = webApplicationContext.getBean("samlEntityID", String.class);
        entityAlias = webApplicationContext.getBean("samlSPAlias", String.class);
    }

    @Test
    void sp_initialized_in_non_snarl_metadata_manager() throws Exception {
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
    void sp_initialization_in_non_snarl_metadata_manager() throws Exception {
        String subdomain = new RandomValueStringGenerator().generate().toLowerCase();
        IdentityZone zone = new IdentityZone();
        zone.setConfig(new IdentityZoneConfiguration());
        zone.setSubdomain(subdomain);
        zone.setId(subdomain);
        zone.setName(subdomain);
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

    String addSubdomainToEntityId(String entityId, String subdomain) {
        if (UaaUrlUtils.isUrl(entityId)) {
            return UaaUrlUtils.addSubdomainToUrl(entityId, subdomain);
        } else {
            return subdomain + "." + entityId;
        }
    }
}
