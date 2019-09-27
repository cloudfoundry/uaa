package org.cloudfoundry.identity.uaa.provider.saml.idp;

import org.junit.Before;
import org.junit.Test;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.provider.saml.idp.SamlServiceProviderDefinition.MetadataLocation.DATA;
import static org.cloudfoundry.identity.uaa.provider.saml.idp.SamlServiceProviderDefinition.MetadataLocation.UNKNOWN;
import static org.cloudfoundry.identity.uaa.provider.saml.idp.SamlServiceProviderDefinition.MetadataLocation.URL;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;

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
    public void no_static_attributes_by_default() {
        assertNotNull(definition.getStaticCustomAttributes());
        assertEquals(0, definition.getStaticCustomAttributes().size());
        Map<String,Object> staticAttributes = new HashMap<>();
        staticAttributes.put("string-value", "string");
        staticAttributes.put("list-value", Collections.singletonList("string"));
        definition.setStaticCustomAttributes(staticAttributes);
        assertNotNull(definition.getStaticCustomAttributes());
        assertEquals(2, definition.getStaticCustomAttributes().size());
        assertSame(staticAttributes, definition.getStaticCustomAttributes());

    }

    @Test
    public void testXmlWithDoctypeFails() {
        definition.setMetaDataLocation(SamlTestUtils.SAML_SP_METADATA.replace("<?xml version=\"1.0\" encoding=\"UTF-8\"?>", "<?xml version=\"1.0\"?>\n<!DOCTYPE>"));
        assertEquals(UNKNOWN, definition.getType());
    }

    @Test
    public void testGetFileTypeFailsAndIsNoLongerSupported() {
        definition.setMetaDataLocation(System.getProperty("user.home"));
        assertEquals(UNKNOWN, definition.getType());
    }

    @Test
    public void testGetUrlTypeMustBeValidUrl() {
        definition.setMetaDataLocation("http");
        assertEquals(UNKNOWN, definition.getType());
    }

    @Test
    public void testGetUrlWhenValid() {
        definition.setMetaDataLocation("http://uaa.com/saml/idp/metadata");
        assertEquals(URL, definition.getType());
    }

    @Test
    public void testGetDataTypeIsValid() {
        definition.setMetaDataLocation("<?xml");
        assertEquals(UNKNOWN, definition.getType());

        definition.setMetaDataLocation("<md:EntityDescriptor");
        assertEquals(UNKNOWN, definition.getType());

        definition.setMetaDataLocation("EntityDescriptor");
        assertEquals(UNKNOWN, definition.getType());
    }

    @Test
    public void testGetDataTypeWhenValid() {
        definition.setMetaDataLocation(SamlTestUtils.SAML_SP_METADATA);
        assertEquals(DATA, definition.getType());
    }

}
