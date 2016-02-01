package org.cloudfoundry.identity.uaa.provider.saml.idp;

import static org.cloudfoundry.identity.uaa.provider.saml.idp.SamlServiceProviderDefinition.MetadataLocation.DATA;
import static org.cloudfoundry.identity.uaa.provider.saml.idp.SamlServiceProviderDefinition.MetadataLocation.UNKNOWN;
import static org.cloudfoundry.identity.uaa.provider.saml.idp.SamlServiceProviderDefinition.MetadataLocation.URL;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import org.apache.commons.httpclient.contrib.ssl.StrictSSLProtocolSocketFactory;
import org.junit.Before;
import org.junit.Test;

public class SamlServiceProviderDefinitionTest {

    SamlServiceProviderDefinition definition;

    @Before
    public void createDefinition() {
        definition = SamlServiceProviderDefinition.Builder.get()
            .setMetaDataLocation("location")
            .setSpEntityId("alias")
            .setNameID("nameID")
            .setMetadataTrustCheck(true)
            .setZoneId("zoneId")
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

    @Test
    public void testGetSocketFactoryClassName() throws Exception {
        SamlServiceProviderDefinition def = new SamlServiceProviderDefinition();
        def.setMetaDataLocation("https://dadas.dadas.dadas/sdada");
        assertEquals("org.apache.commons.httpclient.contrib.ssl.EasySSLProtocolSocketFactory", def.getSocketFactoryClassName());
        def.setMetaDataLocation("http://dadas.dadas.dadas/sdada");
        assertEquals("org.apache.commons.httpclient.protocol.DefaultProtocolSocketFactory", def.getSocketFactoryClassName());
        def.setSocketFactoryClassName("");
        assertEquals("org.apache.commons.httpclient.protocol.DefaultProtocolSocketFactory", def.getSocketFactoryClassName());
        def.setSocketFactoryClassName(null);
        assertEquals("org.apache.commons.httpclient.protocol.DefaultProtocolSocketFactory", def.getSocketFactoryClassName());
        try {
            def.setSocketFactoryClassName("test.class.that.DoesntExist");
            fail("ClassNotFound is expected here");
        } catch (IllegalArgumentException x) {
            assertEquals(ClassNotFoundException.class, x.getCause().getClass());
        }
        def.setSocketFactoryClassName(StrictSSLProtocolSocketFactory.class.getName());
        assertEquals(StrictSSLProtocolSocketFactory.class.getName(), def.getSocketFactoryClassName());
    }
}
