package org.cloudfoundry.identity.uaa.login.saml;

import org.apache.commons.httpclient.contrib.ssl.StrictSSLProtocolSocketFactory;
import org.junit.Test;

import java.io.File;
import java.util.Arrays;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

public class IdentityProviderDefinitionTests {

    @Test
    public void testGetType() throws Exception {
        SamlIdentityProviderDefinition def = new SamlIdentityProviderDefinition();
        def.setMetaDataLocation("<?xml>");
        assertEquals(SamlIdentityProviderDefinition.MetadataLocation.DATA, def.getType());
        def.setMetaDataLocation("https://dadas.dadas.dadas/sdada");
        assertEquals(SamlIdentityProviderDefinition.MetadataLocation.URL, def.getType());
        def.setMetaDataLocation("http://dadas.dadas.dadas/sdada");
        assertEquals(SamlIdentityProviderDefinition.MetadataLocation.URL, def.getType());
        def.setMetaDataLocation("test-file-metadata.xml");
        assertEquals(SamlIdentityProviderDefinition.MetadataLocation.FILE, def.getType());
        File f = new File(System.getProperty("java.io.tmpdir"),IdentityProviderDefinitionTests.class.getName()+".testcase");
        f.createNewFile();
        f.deleteOnExit();
        def.setMetaDataLocation(f.getAbsolutePath());
        assertEquals(SamlIdentityProviderDefinition.MetadataLocation.FILE, def.getType());
        f.delete();
        def.setMetaDataLocation(f.getAbsolutePath());
        assertEquals(SamlIdentityProviderDefinition.MetadataLocation.UNKNOWN, def.getType());


    }

    @Test
    public void testSetIdpEntityAlias() throws Exception {
        SamlIdentityProviderDefinition def = new SamlIdentityProviderDefinition();
        def.setIdpEntityAlias("testalias");
    }

    @Test
    public void testSetEmailDomain() {
        SamlIdentityProviderDefinition def = new SamlIdentityProviderDefinition();
        def.setEmailDomain(Arrays.asList("test.com"));
        assertEquals("test.com", def.getEmailDomain().get(0));
    }


    @Test
    public void testGetSocketFactoryClassName() throws Exception {
        SamlIdentityProviderDefinition def = new SamlIdentityProviderDefinition();
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