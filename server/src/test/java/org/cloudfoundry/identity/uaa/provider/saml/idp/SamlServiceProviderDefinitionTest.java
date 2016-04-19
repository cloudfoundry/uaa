package org.cloudfoundry.identity.uaa.provider.saml.idp;

import static org.cloudfoundry.identity.uaa.provider.saml.idp.SamlServiceProviderDefinition.MetadataLocation.DATA;
import static org.cloudfoundry.identity.uaa.provider.saml.idp.SamlServiceProviderDefinition.MetadataLocation.UNKNOWN;
import static org.cloudfoundry.identity.uaa.provider.saml.idp.SamlServiceProviderDefinition.MetadataLocation.URL;
import static org.junit.Assert.assertEquals;

import org.junit.Before;
import org.junit.Test;

public class SamlServiceProviderDefinitionTest {

    SamlServiceProviderDefinition definition;

    @Before
    public void createDefinition() {
        definition = SamlServiceProviderDefinition.Builder.get()
            .setMetaDataLocation("location")
            .setNameID("nameID")
            .setMetadataTrustCheck(true)
            .build();
    }

    @Test
    public void testXmlWithDoctypeFails() {
        definition.setMetaDataLocation(SamlTestUtils.SAML_SP_METADATA.replace("<?xml version=\"1.0\" encoding=\"UTF-8\"?>", "<?xml version=\"1.0\"?>\n<!DOCTYPE>"));
        assertEquals(UNKNOWN, definition.getType());
    }

    @Test
    public void testGetFileTypeFailsAndIsNoLongerSupported() throws Exception {
        definition.setMetaDataLocation(System.getProperty("user.home"));
        assertEquals(UNKNOWN, definition.getType());
    }

    @Test
    public void testGetUrlTypeMustBeValidUrl() throws Exception {
        definition.setMetaDataLocation("http");
        assertEquals(UNKNOWN, definition.getType());
    }

    @Test
    public void testGetUrlWhenValid() throws Exception {
        definition.setMetaDataLocation("http://login.identity.cf-app.com/saml/idp/metadata");
        assertEquals(URL, definition.getType());
    }

    @Test
    public void testGetDataTypeIsValid() throws Exception {
        definition.setMetaDataLocation("<?xml");
        assertEquals(UNKNOWN, definition.getType());

        definition.setMetaDataLocation("<md:EntityDescriptor");
        assertEquals(UNKNOWN, definition.getType());

        definition.setMetaDataLocation("EntityDescriptor");
        assertEquals(UNKNOWN, definition.getType());
    }

    @Test
    public void testGetDataTypeWhenValid() throws Exception {
        definition.setMetaDataLocation(SamlTestUtils.SAML_SP_METADATA);
        assertEquals(DATA, definition.getType());
    }

}
