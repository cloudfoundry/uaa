package org.cloudfoundry.identity.uaa.provider.saml;

import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.junit.Test;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.metadata.impl.EntityDescriptorImpl;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.parse.BasicParserPool;

import java.io.File;
import java.util.Scanner;

import static org.junit.Assert.*;

public class ConfigMetadataProviderTest {
    @Test
    public void testDoGetMetadata() throws Exception {
        String metadataString = new Scanner(new File("../uaa/src/test/resources/idp.xml")).useDelimiter("\\Z").next();
        ConfigMetadataProvider provider = new ConfigMetadataProvider(IdentityZone.getUaaZoneId(), "testalias", metadataString);
        ConfigMetadataProvider provider2 = new ConfigMetadataProvider(IdentityZone.getUaaZoneId(), "testalias", metadataString);
        DefaultBootstrap.bootstrap();
        provider.setParserPool(new BasicParserPool());
        XMLObject xmlObject = provider.doGetMetadata();
        assertNotNull(xmlObject);
        assertEquals("http://openam.example.com:8181/openam", ((EntityDescriptorImpl) xmlObject).getEntityID());
        assertEquals(provider, provider2);
    }
}