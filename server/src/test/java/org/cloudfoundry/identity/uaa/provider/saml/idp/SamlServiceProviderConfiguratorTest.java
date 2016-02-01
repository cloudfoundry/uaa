package org.cloudfoundry.identity.uaa.provider.saml.idp;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.fail;

import java.util.Timer;

import org.cloudfoundry.identity.uaa.provider.saml.ComparableProvider;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.parse.BasicParserPool;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

public class SamlServiceProviderConfiguratorTest {

    private static final String SINGLE_ADD_ENTITY_ID = "cloudfoundry-saml-login";
    private final SamlTestUtils samlTestUtils = new SamlTestUtils();

    private SamlServiceProviderConfigurator conf = null;
    private SamlServiceProviderDefinition singleAdd = null;
    private SamlServiceProviderDefinition singleAddWithoutHeader = null;

    @Before
    public void setup() throws Exception {
        samlTestUtils.initalize();
        conf = new SamlServiceProviderConfigurator();
        conf.setParserPool(new BasicParserPool());
        singleAdd = SamlServiceProviderDefinition.Builder.get()
                .setMetaDataLocation(String.format(SamlTestUtils.UNSIGNED_SAML_SP_METADATA_WITHOUT_ID,
                        new RandomValueStringGenerator().generate()))
                .setSpEntityId(SINGLE_ADD_ENTITY_ID).setNameID("sample-nameID").setSingleSignOnServiceIndex(1)
                .setMetadataTrustCheck(true).setZoneId("uaa").build();
        singleAddWithoutHeader = SamlServiceProviderDefinition.Builder.get()
                .setMetaDataLocation(String.format(SamlTestUtils.UNSIGNED_SAML_SP_METADATA_WITHOUT_HEADER,
                        new RandomValueStringGenerator().generate()))
                .setSpEntityId(SINGLE_ADD_ENTITY_ID).setNameID("sample-nameID").setSingleSignOnServiceIndex(1)
                .setMetadataTrustCheck(true).setZoneId("uaa").build();
    }

    @Test
    public void testCloneSamlServiceProviderDefinition() throws Exception {
        SamlServiceProviderDefinition clone = singleAdd.clone();
        assertEquals(singleAdd, clone);
        assertNotSame(singleAdd, clone);
    }

    @Test
    public void testAddAndUpdateAndRemoveSamlServiceProviderDefinition() throws Exception {
        conf.addSamlServiceProviderDefinition(singleAdd);
        assertEquals(1, conf.getSamlServiceProviders().size());
        conf.addSamlServiceProviderDefinition(singleAddWithoutHeader);
        assertEquals(1, conf.getSamlServiceProviders().size());
        conf.removeSamlServiceProviderDefinition(singleAdd);
        assertEquals(0, conf.getSamlServiceProviders().size());
    }

    @Test(expected = MetadataProviderException.class)
    public void testAddSamlServiceProviderDefinitionWithConflictingEntityId() throws Exception {
        conf.addSamlServiceProviderDefinition(singleAdd);
        SamlServiceProviderDefinition duplicate = SamlServiceProviderDefinition.Builder.get()
                .setMetaDataLocation(String.format(SamlTestUtils.UNSIGNED_SAML_SP_METADATA_WITHOUT_ID,
                        new RandomValueStringGenerator().generate()))
                .setSpEntityId(SINGLE_ADD_ENTITY_ID + "_2").setNameID("sample-nameID").setSingleSignOnServiceIndex(1)
                .setMetadataTrustCheck(true).setZoneId("uaa").build();
        conf.addSamlServiceProviderDefinition(duplicate);
    }

    @Test(expected = NullPointerException.class)
    public void testAddNullSamlServiceProvider() throws Exception {
        conf.addSamlServiceProviderDefinition(null);
    }

    @Test(expected = NullPointerException.class)
    public void testAddSamlServiceProviderWithNullEntityId() throws Exception {
        singleAdd.setSpEntityId(null);
        conf.addSamlServiceProviderDefinition(singleAdd);
    }

    @Test
    public void testGetEntityID() throws Exception {
        Timer t = new Timer();
        conf.addSamlServiceProviderDefinition(singleAdd);
        for (SamlServiceProviderDefinition def : conf.getSamlServiceProviderDefinitions()) {
            switch (def.getSpEntityId()) {
            case "cloudfoundry-saml-login": {
                ComparableProvider provider = (ComparableProvider) conf.getExtendedMetadataDelegateFromCache(def)
                        .getDelegate();
                assertEquals("cloudfoundry-saml-login", provider.getEntityID());
                break;
            }
            default:
                fail(String.format("Unknown provider %s", def.getSpEntityId()));
            }

        }
        t.cancel();
    }
}
