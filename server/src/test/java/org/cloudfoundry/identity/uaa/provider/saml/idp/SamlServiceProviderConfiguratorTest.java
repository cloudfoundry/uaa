package org.cloudfoundry.identity.uaa.provider.saml.idp;

import static org.cloudfoundry.identity.uaa.provider.saml.idp.SamlTestUtils.MOCK_SP_ENTITY_ID;
import static org.cloudfoundry.identity.uaa.provider.saml.idp.SamlTestUtils.mockSamlServiceProviderForZone;
import static org.cloudfoundry.identity.uaa.provider.saml.idp.SamlTestUtils.mockSamlServiceProviderWithoutXmlHeaderInMetadata;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.util.Map;
import java.util.Timer;
import java.util.UUID;

import org.cloudfoundry.identity.uaa.provider.saml.ComparableProvider;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.parse.BasicParserPool;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

public class SamlServiceProviderConfiguratorTest {

    private final SamlTestUtils samlTestUtils = new SamlTestUtils();

    private SamlServiceProviderConfigurator conf = null;

    @Before
    public void setup() throws Exception {
        samlTestUtils.initalize();
        conf = new SamlServiceProviderConfigurator();
        conf.setParserPool(new BasicParserPool());
    }

    @Test
    public void testAddAndUpdateAndRemoveSamlServiceProvider() throws Exception {
        SamlServiceProvider sp = mockSamlServiceProviderForZone("uaa");
        SamlServiceProvider spNoHeader = mockSamlServiceProviderWithoutXmlHeaderInMetadata();

        conf.addSamlServiceProvider(sp);
        assertEquals(1, conf.getSamlServiceProviders().size());
        conf.addSamlServiceProvider(spNoHeader);
        assertEquals(1, conf.getSamlServiceProviders().size());
        conf.removeSamlServiceProvider(sp.getEntityId());
        assertEquals(0, conf.getSamlServiceProviders().size());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testAddSamlServiceProviderToWrongZone() throws Exception {
        SamlServiceProvider sp = mockSamlServiceProviderForZone("uaa");
        sp.setIdentityZoneId(UUID.randomUUID().toString());
        conf.addSamlServiceProvider(sp);
    }

    @Test
    public void testGetSamlServiceProviderMapForZone() throws Exception {
        try {
            String zoneId = UUID.randomUUID().toString();
            SamlServiceProvider sp = mockSamlServiceProviderForZone("uaa");
            sp.setIdentityZoneId(zoneId);
            IdentityZoneHolder.set(new IdentityZone().setId(zoneId));
            conf.addSamlServiceProvider(sp);
    
            String unwantedZoneId = UUID.randomUUID().toString();
            SamlServiceProvider unwantedSp = mockSamlServiceProviderForZone("uaa");
            unwantedSp.setIdentityZoneId(unwantedZoneId);
            IdentityZoneHolder.set(new IdentityZone().setId(unwantedZoneId));
            conf.addSamlServiceProvider(unwantedSp);
    
            IdentityZone zone = new IdentityZone().setId(zoneId);
            Map<String, SamlServiceProviderHolder> spMap = conf.getSamlServiceProviderMapForZone(zone);
            assertEquals(1, spMap.entrySet().size());
            assertEquals(sp, spMap.get(sp.getEntityId()).getSamlServiceProvider());
        }
        finally {
            IdentityZoneHolder.set(IdentityZone.getUaa());
        }
    }

    @Test(expected = MetadataProviderException.class)
    public void testAddSamlServiceProviderWithConflictingEntityId() throws Exception {
        SamlServiceProvider sp = mockSamlServiceProviderForZone("uaa");

        conf.addSamlServiceProvider(sp);
        SamlServiceProviderDefinition duplicateDef = SamlServiceProviderDefinition.Builder.get()
                .setMetaDataLocation(String.format(SamlTestUtils.UNSIGNED_SAML_SP_METADATA_WITHOUT_ID,
                        new RandomValueStringGenerator().generate()))
                .setNameID("sample-nameID").setSingleSignOnServiceIndex(1)
                .setMetadataTrustCheck(true).build();
        SamlServiceProvider duplicate = new SamlServiceProvider().setEntityId(MOCK_SP_ENTITY_ID + "_2").setIdentityZoneId("uaa")
                .setConfig(duplicateDef);
        conf.addSamlServiceProvider(duplicate);
    }

    @Test(expected = NullPointerException.class)
    public void testAddNullSamlServiceProvider() throws Exception {
        conf.addSamlServiceProvider(null);
    }

    @Test(expected = NullPointerException.class)
    public void testAddSamlServiceProviderWithNullEntityId() throws Exception {
        SamlServiceProvider sp = mockSamlServiceProviderForZone("uaa");
        sp.setEntityId(null);
        conf.addSamlServiceProvider(sp);
    }

    @Test(expected = NullPointerException.class)
    public void testAddSamlServiceProviderWithNullIdentityZoneId() throws Exception {
        SamlServiceProvider sp = mockSamlServiceProviderForZone("uaa");
        sp.setIdentityZoneId(null);
        conf.addSamlServiceProvider(sp);
    }

    @Test
    public void testGetEntityId() throws Exception {
        Timer t = new Timer();
        conf.addSamlServiceProvider(mockSamlServiceProviderForZone("uaa"));
        for (SamlServiceProviderHolder holder : conf.getSamlServiceProviders()) {
            SamlServiceProvider provider = holder.getSamlServiceProvider();
            switch (provider.getEntityId()) {
            case "cloudfoundry-saml-login": {
                ComparableProvider compProvider = (ComparableProvider) conf.getExtendedMetadataDelegateFromCache(provider.getEntityId())
                        .getDelegate();
                assertEquals("cloudfoundry-saml-login", compProvider.getEntityID());
                break;
            }
            default:
                fail(String.format("Unknown provider %s", provider.getEntityId()));
            }

        }
        t.cancel();
    }
}
