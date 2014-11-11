package org.cloudfoundry.identity.uaa.login.saml;

import org.apache.commons.httpclient.contrib.ssl.StrictSSLProtocolSocketFactory;
import org.junit.Test;

import java.io.File;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

public class IdentityProviderDefinitionTests {

    @Test
    public void testGetType() throws Exception {
        IdentityProviderDefinition def = new IdentityProviderDefinition();
        def.setMetaDataLocation("<?xml>");
        assertEquals(IdentityProviderDefinition.MetadataLocation.DATA, def.getType());
        def.setMetaDataLocation("https://dadas.dadas.dadas/sdada");
        assertEquals(IdentityProviderDefinition.MetadataLocation.URL, def.getType());
        def.setMetaDataLocation("http://dadas.dadas.dadas/sdada");
        assertEquals(IdentityProviderDefinition.MetadataLocation.URL, def.getType());
        def.setMetaDataLocation("sample-okta-localhost.xml");
        assertEquals(IdentityProviderDefinition.MetadataLocation.FILE, def.getType());
        File f = new File(System.getProperty("java.io.tmpdir"),IdentityProviderDefinitionTests.class.getName()+".testcase");
        f.createNewFile();
        f.deleteOnExit();
        def.setMetaDataLocation(f.getAbsolutePath());
        assertEquals(IdentityProviderDefinition.MetadataLocation.FILE, def.getType());
        f.delete();
        def.setMetaDataLocation(f.getAbsolutePath());
        assertEquals(IdentityProviderDefinition.MetadataLocation.UNKNOWN, def.getType());


    }

    @Test
    public void testSetIdpEntityAlias() throws Exception {
        IdentityProviderDefinition def = new IdentityProviderDefinition();
        def.setIdpEntityAlias("testalias");
    }


    @Test(expected = NullPointerException.class)
    public void testSetNullIdpEntityAlias() throws Exception {
        IdentityProviderDefinition def = new IdentityProviderDefinition();
        def.setIdpEntityAlias(null);
    }

    @Test
    public void testGetSocketFactoryClassName() throws Exception {
        IdentityProviderDefinition def = new IdentityProviderDefinition();
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
        try {
            def.setSocketFactoryClassName("java.lang.Object");
            fail("ClassCastException is expected here");
        } catch (IllegalArgumentException x) {
            assertEquals(ClassCastException.class, x.getCause().getClass());
        }
        def.setSocketFactoryClassName(StrictSSLProtocolSocketFactory.class.getName());
        assertEquals(StrictSSLProtocolSocketFactory.class.getName(), def.getSocketFactoryClassName());


    }
}