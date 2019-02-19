package org.cloudfoundry.identity.uaa.provider.saml;

import java.io.File;
import java.lang.reflect.Field;
import java.util.Arrays;

import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.util.JsonUtils;

import org.junit.Before;
import org.junit.Test;
import org.springframework.util.ReflectionUtils;

import static org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition.MetadataLocation.DATA;
import static org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition.MetadataLocation.UNKNOWN;
import static org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition.MetadataLocation.URL;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class SamlIdentityProviderDefinitionTests {

    SamlIdentityProviderDefinition definition;

    @Before
    public void createDefinition() {
        definition = buildSamlIdentityProviderDefinition();
    }

    private SamlIdentityProviderDefinition buildSamlIdentityProviderDefinition() {
        return new SamlIdentityProviderDefinition()
            .setMetaDataLocation("location")
            .setIdpEntityAlias("alias")
            .setNameID("nameID")
            .setMetadataTrustCheck(true)
            .setShowSamlLink(false)
            .setLinkText("link test")
            .setIconUrl("url")
            .setZoneId("zoneId");
    }

    @Test
    public void testEquals() {
        definition.setAddShadowUserOnLogin(true);

        SamlIdentityProviderDefinition definition2 = buildSamlIdentityProviderDefinition();
        definition2.setAddShadowUserOnLogin(false);

        assertNotEquals(definition, definition2);

        definition2.setAddShadowUserOnLogin(true);
        assertEquals(definition, definition2);
    }

    @Test
    public void test_serialize_custom_attributes_field() {
        definition.setStoreCustomAttributes(true);
        SamlIdentityProviderDefinition def = JsonUtils.readValue(JsonUtils.writeValueAsString(definition), SamlIdentityProviderDefinition.class);
        assertTrue(def.isStoreCustomAttributes());
    }

    @Test
    public void testGetType() throws Exception {
        SamlIdentityProviderDefinition def = new SamlIdentityProviderDefinition();
        def.setMetaDataLocation("<?xml>");
        assertEquals(SamlIdentityProviderDefinition.MetadataLocation.UNKNOWN, def.getType());
        def.setMetaDataLocation("https://dadas.dadas.dadas/sdada");
        assertEquals(SamlIdentityProviderDefinition.MetadataLocation.URL, def.getType());
        def.setMetaDataLocation("http://dadas.dadas.dadas/sdada");
        assertEquals(SamlIdentityProviderDefinition.MetadataLocation.URL, def.getType());

        def.setMetaDataLocation("test-file-metadata.xml");
        assertEquals(SamlIdentityProviderDefinition.MetadataLocation.UNKNOWN, def.getType());

        File f = new File(System.getProperty("java.io.tmpdir"),SamlIdentityProviderDefinitionTests.class.getName()+".testcase");
        f.createNewFile();
        f.deleteOnExit();
        def.setMetaDataLocation(f.getAbsolutePath());
        assertEquals(SamlIdentityProviderDefinition.MetadataLocation.UNKNOWN, def.getType());
        f.delete();
        def.setMetaDataLocation(f.getAbsolutePath());
        assertEquals(SamlIdentityProviderDefinition.MetadataLocation.UNKNOWN, def.getType());
    }

    @Test
    public void test_XML_with_DOCTYPE_Fails() {
        definition.setMetaDataLocation(IDP_METADATA.replace("<?xml version=\"1.0\"?>\n", "<?xml version=\"1.0\"?>\n<!DOCTYPE>"));
        assertEquals(UNKNOWN, definition.getType());
    }

    @Test
    public void test_clone() throws Exception {
        definition.setMetaDataLocation("http://dadas.dadas.dadas/sdada");
        definition.setSkipSslValidation(true);
        definition.setStoreCustomAttributes(true);
        SamlIdentityProviderDefinition def = definition.clone();
        ReflectionUtils.doWithFields(SamlIdentityProviderDefinition.class,
                                     new ReflectionUtils.FieldCallback() {
                                         @Override
                                         public void doWith(Field f) throws IllegalArgumentException, IllegalAccessException {
                                             f.setAccessible(true);
                                             f.setAccessible(true);
                                             Object expectedValue = f.get(definition);
                                             Object actualValue = f.get(def);
                                             assertEquals(f.getName(), expectedValue, actualValue);
                                         }
                                     });


    }

    @Test
    public void test_Get_FileType_Fails_and_is_No_Longer_Supported() throws Exception {
        definition.setMetaDataLocation(System.getProperty("user.home"));
        assertEquals(UNKNOWN, definition.getType());
    }

    @Test
    public void test_Get_URL_Type_Must_Be_Valid_URL() throws Exception {
        definition.setMetaDataLocation("http");
        assertEquals(UNKNOWN, definition.getType());
    }

    @Test
    public void test_Get_URL_When_Valid() throws Exception {
        definition.setMetaDataLocation("http://uaa.com/saml/metadata");
        assertEquals(URL, definition.getType());
    }

    @Test
    public void test_Get_Data_Type_Must_Be_Valid_Data() throws Exception {
        definition.setMetaDataLocation("<?xml");
        assertEquals(UNKNOWN, definition.getType());

        definition.setMetaDataLocation("<md:EntityDescriptor");
        assertEquals(UNKNOWN, definition.getType());

        definition.setMetaDataLocation("EntityDescriptor");
        assertEquals(UNKNOWN, definition.getType());
    }

    @Test
    public void test_Get_Data_Type_When_Valid() throws Exception {
        definition.setMetaDataLocation(IDP_METADATA);
        assertEquals(DATA, definition.getType());
    }

    public static final String ALIAS = "alias";
    public static final String IDP_METADATA = "<?xml version=\"1.0\"?>\n" +
        "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" entityID=\"http://"+ALIAS+".cfapps.io/saml2/idp/metadata.php\" ID=\"pfx06ad4153-c17c-d286-194c-dec30bb92796\"><ds:Signature>\n" +
        "  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
        "    <ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>\n" +
        "  <ds:Reference URI=\"#pfx06ad4153-c17c-d286-194c-dec30bb92796\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><ds:DigestValue>begl1WVCsXSn7iHixtWPP8d/X+k=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>BmbKqA3A0oSLcn5jImz/l5WbpVXj+8JIpT/ENWjOjSd/gcAsZm1QvYg+RxYPBk+iV2bBxD+/yAE/w0wibsHrl0u9eDhoMRUJBUSmeyuN1lYzBuoVa08PdAGtb5cGm4DMQT5Rzakb1P0hhEPPEDDHgTTxop89LUu6xx97t2Q03Khy8mXEmBmNt2NlFxJPNt0FwHqLKOHRKBOE/+BpswlBocjOQKFsI9tG3TyjFC68mM2jo0fpUQCgj5ZfhzolvS7z7c6V201d9Tqig0/mMFFJLTN8WuZPavw22AJlMjsDY9my+4R9HKhK5U53DhcTeECs9fb4gd7p5BJy4vVp7tqqOg==</ds:SignatureValue>\n" +
        "<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIEEzCCAvugAwIBAgIJAIc1qzLrv+5nMA0GCSqGSIb3DQEBCwUAMIGfMQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ08xFDASBgNVBAcMC0Nhc3RsZSBSb2NrMRwwGgYDVQQKDBNTYW1sIFRlc3RpbmcgU2VydmVyMQswCQYDVQQLDAJJVDEgMB4GA1UEAwwXc2ltcGxlc2FtbHBocC5jZmFwcHMuaW8xIDAeBgkqhkiG9w0BCQEWEWZoYW5pa0BwaXZvdGFsLmlvMB4XDTE1MDIyMzIyNDUwM1oXDTI1MDIyMjIyNDUwM1owgZ8xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDTzEUMBIGA1UEBwwLQ2FzdGxlIFJvY2sxHDAaBgNVBAoME1NhbWwgVGVzdGluZyBTZXJ2ZXIxCzAJBgNVBAsMAklUMSAwHgYDVQQDDBdzaW1wbGVzYW1scGhwLmNmYXBwcy5pbzEgMB4GCSqGSIb3DQEJARYRZmhhbmlrQHBpdm90YWwuaW8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4cn62E1xLqpN34PmbrKBbkOXFjzWgJ9b+pXuaRft6A339uuIQeoeH5qeSKRVTl32L0gdz2ZivLwZXW+cqvftVW1tvEHvzJFyxeTW3fCUeCQsebLnA2qRa07RkxTo6Nf244mWWRDodcoHEfDUSbxfTZ6IExSojSIU2RnD6WllYWFdD1GFpBJOmQB8rAc8wJIBdHFdQnX8Ttl7hZ6rtgqEYMzYVMuJ2F2r1HSU1zSAvwpdYP6rRGFRJEfdA9mm3WKfNLSc5cljz0X/TXy0vVlAV95l9qcfFzPmrkNIst9FZSwpvB49LyAVke04FQPPwLgVH4gphiJH3jvZ7I+J5lS8VAgMBAAGjUDBOMB0GA1UdDgQWBBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAfBgNVHSMEGDAWgBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAvMS4EQeP/ipV4jOG5lO6/tYCb/iJeAduOnRhkJk0DbX329lDLZhTTL/x/w/9muCVcvLrzEp6PN+VWfw5E5FWtZN0yhGtP9R+vZnrV+oc2zGD+no1/ySFOe3EiJCO5dehxKjYEmBRv5sU/LZFKZpozKN/BMEa6CqLuxbzb7ykxVr7EVFXwltPxzE9TmL9OACNNyF5eJHWMRMllarUvkcXlh4pux4ks9e6zV9DQBy2zds9f1I3qxg0eX6JnGrXi/ZiCT+lJgVe3ZFXiejiLAiKB04sXW3ti0LW3lx13Y1YlQ4/tlpgTgfIJxKV6nyPiLoK0nywbMd+vpAirDt2Oc+hk</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>\n" +
        "  <md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">\n" +
        "    <md:KeyDescriptor use=\"signing\">\n" +
        "      <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
        "        <ds:X509Data>\n" +
        "          <ds:X509Certificate>MIIEEzCCAvugAwIBAgIJAIc1qzLrv+5nMA0GCSqGSIb3DQEBCwUAMIGfMQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ08xFDASBgNVBAcMC0Nhc3RsZSBSb2NrMRwwGgYDVQQKDBNTYW1sIFRlc3RpbmcgU2VydmVyMQswCQYDVQQLDAJJVDEgMB4GA1UEAwwXc2ltcGxlc2FtbHBocC5jZmFwcHMuaW8xIDAeBgkqhkiG9w0BCQEWEWZoYW5pa0BwaXZvdGFsLmlvMB4XDTE1MDIyMzIyNDUwM1oXDTI1MDIyMjIyNDUwM1owgZ8xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDTzEUMBIGA1UEBwwLQ2FzdGxlIFJvY2sxHDAaBgNVBAoME1NhbWwgVGVzdGluZyBTZXJ2ZXIxCzAJBgNVBAsMAklUMSAwHgYDVQQDDBdzaW1wbGVzYW1scGhwLmNmYXBwcy5pbzEgMB4GCSqGSIb3DQEJARYRZmhhbmlrQHBpdm90YWwuaW8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4cn62E1xLqpN34PmbrKBbkOXFjzWgJ9b+pXuaRft6A339uuIQeoeH5qeSKRVTl32L0gdz2ZivLwZXW+cqvftVW1tvEHvzJFyxeTW3fCUeCQsebLnA2qRa07RkxTo6Nf244mWWRDodcoHEfDUSbxfTZ6IExSojSIU2RnD6WllYWFdD1GFpBJOmQB8rAc8wJIBdHFdQnX8Ttl7hZ6rtgqEYMzYVMuJ2F2r1HSU1zSAvwpdYP6rRGFRJEfdA9mm3WKfNLSc5cljz0X/TXy0vVlAV95l9qcfFzPmrkNIst9FZSwpvB49LyAVke04FQPPwLgVH4gphiJH3jvZ7I+J5lS8VAgMBAAGjUDBOMB0GA1UdDgQWBBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAfBgNVHSMEGDAWgBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAvMS4EQeP/ipV4jOG5lO6/tYCb/iJeAduOnRhkJk0DbX329lDLZhTTL/x/w/9muCVcvLrzEp6PN+VWfw5E5FWtZN0yhGtP9R+vZnrV+oc2zGD+no1/ySFOe3EiJCO5dehxKjYEmBRv5sU/LZFKZpozKN/BMEa6CqLuxbzb7ykxVr7EVFXwltPxzE9TmL9OACNNyF5eJHWMRMllarUvkcXlh4pux4ks9e6zV9DQBy2zds9f1I3qxg0eX6JnGrXi/ZiCT+lJgVe3ZFXiejiLAiKB04sXW3ti0LW3lx13Y1YlQ4/tlpgTgfIJxKV6nyPiLoK0nywbMd+vpAirDt2Oc+hk</ds:X509Certificate>\n" +
        "        </ds:X509Data>\n" +
        "      </ds:KeyInfo>\n" +
        "    </md:KeyDescriptor>\n" +
        "    <md:KeyDescriptor use=\"encryption\">\n" +
        "      <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
        "        <ds:X509Data>\n" +
        "          <ds:X509Certificate>MIIEEzCCAvugAwIBAgIJAIc1qzLrv+5nMA0GCSqGSIb3DQEBCwUAMIGfMQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ08xFDASBgNVBAcMC0Nhc3RsZSBSb2NrMRwwGgYDVQQKDBNTYW1sIFRlc3RpbmcgU2VydmVyMQswCQYDVQQLDAJJVDEgMB4GA1UEAwwXc2ltcGxlc2FtbHBocC5jZmFwcHMuaW8xIDAeBgkqhkiG9w0BCQEWEWZoYW5pa0BwaXZvdGFsLmlvMB4XDTE1MDIyMzIyNDUwM1oXDTI1MDIyMjIyNDUwM1owgZ8xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDTzEUMBIGA1UEBwwLQ2FzdGxlIFJvY2sxHDAaBgNVBAoME1NhbWwgVGVzdGluZyBTZXJ2ZXIxCzAJBgNVBAsMAklUMSAwHgYDVQQDDBdzaW1wbGVzYW1scGhwLmNmYXBwcy5pbzEgMB4GCSqGSIb3DQEJARYRZmhhbmlrQHBpdm90YWwuaW8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4cn62E1xLqpN34PmbrKBbkOXFjzWgJ9b+pXuaRft6A339uuIQeoeH5qeSKRVTl32L0gdz2ZivLwZXW+cqvftVW1tvEHvzJFyxeTW3fCUeCQsebLnA2qRa07RkxTo6Nf244mWWRDodcoHEfDUSbxfTZ6IExSojSIU2RnD6WllYWFdD1GFpBJOmQB8rAc8wJIBdHFdQnX8Ttl7hZ6rtgqEYMzYVMuJ2F2r1HSU1zSAvwpdYP6rRGFRJEfdA9mm3WKfNLSc5cljz0X/TXy0vVlAV95l9qcfFzPmrkNIst9FZSwpvB49LyAVke04FQPPwLgVH4gphiJH3jvZ7I+J5lS8VAgMBAAGjUDBOMB0GA1UdDgQWBBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAfBgNVHSMEGDAWgBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAvMS4EQeP/ipV4jOG5lO6/tYCb/iJeAduOnRhkJk0DbX329lDLZhTTL/x/w/9muCVcvLrzEp6PN+VWfw5E5FWtZN0yhGtP9R+vZnrV+oc2zGD+no1/ySFOe3EiJCO5dehxKjYEmBRv5sU/LZFKZpozKN/BMEa6CqLuxbzb7ykxVr7EVFXwltPxzE9TmL9OACNNyF5eJHWMRMllarUvkcXlh4pux4ks9e6zV9DQBy2zds9f1I3qxg0eX6JnGrXi/ZiCT+lJgVe3ZFXiejiLAiKB04sXW3ti0LW3lx13Y1YlQ4/tlpgTgfIJxKV6nyPiLoK0nywbMd+vpAirDt2Oc+hk</ds:X509Certificate>\n" +
        "        </ds:X509Data>\n" +
        "      </ds:KeyInfo>\n" +
        "    </md:KeyDescriptor>\n" +
        "    <md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"http://"+ALIAS+".cfapps.io/saml2/idp/SingleLogoutService.php\"/>\n" +
        "    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>\n" +
        "    <md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"http://"+ALIAS+".cfapps.io/saml2/idp/SSOService.php\"/>\n" +
        "  </md:IDPSSODescriptor>\n" +
        "  <md:ContactPerson contactType=\"technical\">\n" +
        "    <md:GivenName>Filip</md:GivenName>\n" +
        "    <md:SurName>Hanik</md:SurName>\n" +
        "    <md:EmailAddress>fhanik@pivotal.io</md:EmailAddress>\n" +
        "  </md:ContactPerson>\n" +
        "</md:EntityDescriptor>";

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
    public void testDefaultAuthnContext() {
        SamlIdentityProviderDefinition def = new SamlIdentityProviderDefinition();
        assertEquals(null, def.getAuthnContext());
    }

    @Test
    public void testSetAuthnContext() {
        SamlIdentityProviderDefinition def = new SamlIdentityProviderDefinition();
        def.setAuthnContext(Arrays.asList("a-custom-context"));
        assertEquals("a-custom-context", def.getAuthnContext().get(0));
    }

    @Test
    public void testGetSocketFactoryClassName() throws Exception {
        SamlIdentityProviderDefinition def = new SamlIdentityProviderDefinition();
        def.setMetaDataLocation("https://dadas.dadas.dadas/sdada");
        assertNull(def.getSocketFactoryClassName());
        def.setMetaDataLocation("http://dadas.dadas.dadas/sdada");
        assertNull(def.getSocketFactoryClassName());
        def.setSocketFactoryClassName("");
        assertNull(def.getSocketFactoryClassName());
        def.setSocketFactoryClassName(null);
        assertNull(def.getSocketFactoryClassName());
        def.setSocketFactoryClassName("test.class.that.DoesntExist");
        assertNull(def.getSocketFactoryClassName());

    }
}
