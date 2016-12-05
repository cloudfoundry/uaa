package org.cloudfoundry.identity.uaa.provider.saml.idp;

import org.cloudfoundry.identity.uaa.provider.saml.ComparableProvider;
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
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate;

import java.util.Map;
import java.util.Timer;
import java.util.UUID;

import static org.cloudfoundry.identity.uaa.provider.saml.idp.SamlTestUtils.MOCK_SP_ENTITY_ID;
import static org.cloudfoundry.identity.uaa.provider.saml.idp.SamlTestUtils.mockSamlServiceProvider;
import static org.cloudfoundry.identity.uaa.provider.saml.idp.SamlTestUtils.mockSamlServiceProviderForZone;
import static org.cloudfoundry.identity.uaa.provider.saml.idp.SamlTestUtils.mockSamlServiceProviderForZoneWithoutSPSSOInMetadata;
import static org.cloudfoundry.identity.uaa.provider.saml.idp.SamlTestUtils.mockSamlServiceProviderWithoutXmlHeaderInMetadata;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;


public class SamlServiceProviderConfiguratorTest {

    private final SamlTestUtils samlTestUtils = new SamlTestUtils();

    private SamlServiceProviderConfigurator conf = null;

    @Rule
    public ExpectedException expectedEx = ExpectedException.none();

    @Before
    public void setup() throws Exception {
        samlTestUtils.initalize();
        conf = new SamlServiceProviderConfigurator();
        conf.setParserPool(new BasicParserPool());
    }

    @After
    public void cleanupTestMethod() {
        expectedEx = ExpectedException.none();
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

    @Test
    public void testAddSamlServiceProviderWithNoNameIDFormats() throws Exception {
        SamlServiceProvider sp = mockSamlServiceProvider("uaa", "");

        assertEquals(0, conf.getSamlServiceProviders().size());
        conf.addSamlServiceProvider(sp);
        assertEquals(1, conf.getSamlServiceProviders().size());
        conf.removeSamlServiceProvider(sp.getEntityId());
        assertEquals(0, conf.getSamlServiceProviders().size());
    }

    @Test
    public void testAddSamlServiceProviderWithUnsupportedNameIDFormats() throws Exception {
        String entityId = "uaa";
        expectedEx.expect(MetadataProviderException.class);
        expectedEx.expectMessage("UAA does not support any of the NameIDFormats specified in the metadata for entity: "
                + entityId);
        SamlServiceProvider sp = mockSamlServiceProvider(entityId,
                "<md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>");
        conf.addSamlServiceProvider(sp);
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

    @Test
    public void testNullSSODescriptor() throws Exception {
        ExtendedMetadataDelegate[] delegates =
            conf.addSamlServiceProvider(mockSamlServiceProviderForZoneWithoutSPSSOInMetadata("uaa"));
        assertEquals(delegates.length, 2);
    }

    @Test
    public void testGetNonExistentServiceProviderMetadata() throws Exception {
       Assert.assertNull(conf.getExtendedMetadataDelegateFromCache("non-existent-entity-id"));
    }

    @Test
    public void testRemoveNonExistentServiceProviderMetadata() throws Exception {
       Assert.assertNull(conf.removeSamlServiceProvider("non-existent-entity-id"));
    }

}
