/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.login.saml;

import org.apache.commons.io.FileUtils;
import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.SetServerNameRequestPostProcessor;
import org.cloudfoundry.identity.uaa.zone.IdentityProvider;
import org.cloudfoundry.identity.uaa.zone.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.hamcrest.Matchers;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate;

import java.io.File;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.springframework.http.MediaType.TEXT_HTML;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.xpath;

/**
 * This test ensures that UAA instances properly refresh the SAML providers from the database.
 */
public class SamlIDPRefreshMockMvcTests extends InjectedMockContextTest {
    public static final String IDP_META_DATA = "<?xml version=\"1.0\"?>\n" +
        "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" entityID=\"http://simplesamlphp.cfapps.io/saml2/idp/metadata.php\" ID=\"pfx06ad4153-c17c-d286-194c-dec30bb92796\"><ds:Signature>\n" +
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
        "    <md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"http://simplesamlphp.cfapps.io/saml2/idp/SingleLogoutService.php\"/>\n" +
        "    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>\n" +
        "    <md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"http://simplesamlphp.cfapps.io/saml2/idp/SSOService.php\"/>\n" +
        "  </md:IDPSSODescriptor>\n" +
        "  <md:ContactPerson contactType=\"technical\">\n" +
        "    <md:GivenName>Filip</md:GivenName>\n" +
        "    <md:SurName>Hanik</md:SurName>\n" +
        "    <md:EmailAddress>fhanik@pivotal.io</md:EmailAddress>\n" +
        "  </md:ContactPerson>\n" +
        "</md:EntityDescriptor>";
    private UaaTestAccounts testAccounts;

    private JdbcTemplate jdbcTemplate;

    private IdentityProviderProvisioning providerProvisioning;

    private ZoneAwareMetadataManager zoneAwareMetadataManager;

    private IdentityZoneProvisioning zoneProvisioning;

    private IdentityProviderConfigurator configurator;

    @Before
    public void setUpContext() throws Exception {
        SecurityContextHolder.clearContext();
        testAccounts = UaaTestAccounts.standard(null);
        jdbcTemplate = getWebApplicationContext().getBean(JdbcTemplate.class);
        providerProvisioning = getWebApplicationContext().getBean(IdentityProviderProvisioning.class);
        zoneAwareMetadataManager = getWebApplicationContext().getBean(ZoneAwareMetadataManager.class);
        zoneProvisioning = getWebApplicationContext().getBean(IdentityZoneProvisioning.class);
        configurator = getWebApplicationContext().getBean(IdentityProviderConfigurator.class);
        //ensure that we don't fire the listener, we want to test the DB refresh
        getWebApplicationContext().getBean(ProviderChangedListener.class).setMetadataManager(null);
        cleanSamlProviders();

    }

    @After
    public void cleanSamlProviders() throws Exception {
        for (IdentityZone zone : zoneProvisioning.retrieveAll()) {
            for (IdentityProvider provider : providerProvisioning.retrieveAll(false, zone.getId())) {
                if (Origin.SAML.equals(provider.getType())) {
                    ZoneAwareMetadataManager.ExtensionMetadataManager manager = zoneAwareMetadataManager.getManager(zone);
                    IdentityProviderDefinition definition = provider.getConfigValue(IdentityProviderDefinition.class);
                    ExtendedMetadataDelegate delegate = configurator.getExtendedMetadataDelegate(definition);
                    configurator.removeIdentityProviderDefinition(definition);
                    manager.removeMetadataProvider(delegate);
                    jdbcTemplate.update("delete from identity_provider where id='"+provider.getId()+"'");
                }
            }
            getMockMvc().perform(post("/saml/metadata").with(new SetServerNameRequestPostProcessor(zone.getSubdomain() + ".localhost")));
            //all we have left is the local provider
            assertEquals(1, zoneAwareMetadataManager.getManager(zone).getAvailableProviders().size());
        }
        SecurityContextHolder.clearContext();
        IdentityZoneHolder.clear();
    }

    @Test
    public void testThatDBAddedXMLProviderShowsOnLoginPage() throws Exception {
        assertEquals(1, zoneAwareMetadataManager.getAvailableProviders().size());
        IdentityProvider provider = createSamlProvider(IDP_META_DATA);
        IdentityProviderDefinition definition = provider.getConfigValue(IdentityProviderDefinition.class);
        //ensure that the listener was not the one who created the provider
        assertEquals(1, zoneAwareMetadataManager.getAvailableProviders().size());
        //this simulates what the timer does
        zoneAwareMetadataManager.refreshAllProviders();
        assertEquals(2, zoneAwareMetadataManager.getAvailableProviders().size());

        //ensure that we have an actual SAML provider created


        //ensure that it exists in the link
        getMockMvc().perform(get("/login").accept(TEXT_HTML))
            .andExpect(status().isOk())
            .andExpect(xpath("//a[text()='" + definition.getLinkText() + "']").exists());
    }

    @Test
    public void testThatDBXMLDisabledProvider() throws Exception {
        assertEquals(1, zoneAwareMetadataManager.getAvailableProviders().size());
        IdentityProvider provider = createSamlProvider(IDP_META_DATA);
        IdentityProviderDefinition definition = provider.getConfigValue(IdentityProviderDefinition.class);
        //ensure that the listener was not the one who created the provider
        assertEquals(1, zoneAwareMetadataManager.getAvailableProviders().size());

        //this simulates what the timer does
        zoneAwareMetadataManager.refreshAllProviders();

        //ensure that we have an actual SAML provider created
        assertEquals(2, zoneAwareMetadataManager.getAvailableProviders().size());

        //ensure that it exists in the link
        getMockMvc().perform(get("/login").accept(TEXT_HTML))
            .andExpect(status().isOk())
            .andExpect(xpath("//a[text()='" + definition.getLinkText() + "']").exists());

        provider.setActive(false);
        provider = providerProvisioning.update(provider);
        definition = provider.getConfigValue(IdentityProviderDefinition.class);

        //this simulates what the timer does
        zoneAwareMetadataManager.refreshAllProviders();

        //ensure that we have an actual SAML provider created
        assertEquals(1, zoneAwareMetadataManager.getAvailableProviders().size());

        //ensure that it exists in the link
        getMockMvc().perform(get("/login").accept(TEXT_HTML))
            .andExpect(status().isOk())
            .andExpect(xpath("//a[text()='" + definition.getLinkText() + "']").doesNotExist());
    }

    @Test
    public void testThatDBAddedFileProviderShowsOnLoginPage() throws Exception {
        assertEquals(1, zoneAwareMetadataManager.getAvailableProviders().size());
        IdentityProvider provider = createSamlProvider(getMetadataFile(IDP_META_DATA).getAbsolutePath());
        IdentityProviderDefinition definition = provider.getConfigValue(IdentityProviderDefinition.class);
        //ensure that the listener was not the one who created the provider
        assertEquals(1, zoneAwareMetadataManager.getAvailableProviders().size());

        //this simulates what the timer does
        zoneAwareMetadataManager.refreshAllProviders();
        assertEquals(2, zoneAwareMetadataManager.getAvailableProviders().size());

        //ensure that we have an actual SAML provider created


        //ensure that it exists in the link
        getMockMvc().perform(get("/login").accept(TEXT_HTML))
            .andExpect(status().isOk())
            .andExpect(xpath("//a[text()='" + definition.getLinkText() + "']").exists());
    }

    @Test
    public void testThatDBFileDisabledProvider() throws Exception {
        assertEquals(1, zoneAwareMetadataManager.getAvailableProviders().size());
        IdentityProvider provider = createSamlProvider(getMetadataFile(IDP_META_DATA).getAbsolutePath());
        IdentityProviderDefinition definition = provider.getConfigValue(IdentityProviderDefinition.class);
        //ensure that the listener was not the one who created the provider
        assertEquals(1, zoneAwareMetadataManager.getAvailableProviders().size());

        //this simulates what the timer does
        zoneAwareMetadataManager.refreshAllProviders();

        //ensure that we have an actual SAML provider created
        assertEquals(2, zoneAwareMetadataManager.getAvailableProviders().size());

        //ensure that it exists in the link
        getMockMvc().perform(get("/login").accept(TEXT_HTML))
            .andExpect(status().isOk())
            .andExpect(xpath("//a[text()='" + definition.getLinkText() + "']").exists());

        provider.setActive(false);
        provider = providerProvisioning.update(provider);
        definition = provider.getConfigValue(IdentityProviderDefinition.class);

        //this simulates what the timer does
        zoneAwareMetadataManager.refreshAllProviders();

        //ensure that we have an actual SAML provider created
        assertEquals(1, zoneAwareMetadataManager.getAvailableProviders().size());

        //ensure that it exists in the link
        getMockMvc().perform(get("/login").accept(TEXT_HTML))
            .andExpect(status().isOk())
            .andExpect(xpath("//a[text()='" + definition.getLinkText() + "']").doesNotExist());
    }

    @Test
    public void testThatDBAddedUrlProviderShowsOnLoginPage() throws Exception {
        assertEquals(1, zoneAwareMetadataManager.getAvailableProviders().size());
        IdentityProvider provider = createSamlProvider("http://simplesamlphp.cfapps.io/saml2/idp/metadata.php");
        IdentityProviderDefinition definition = provider.getConfigValue(IdentityProviderDefinition.class);
        //ensure that the listener was not the one who created the provider
        assertEquals(1, zoneAwareMetadataManager.getAvailableProviders().size());

        //this simulates what the timer does
        zoneAwareMetadataManager.refreshAllProviders();
        assertEquals(2, zoneAwareMetadataManager.getAvailableProviders().size());

        //ensure that we have an actual SAML provider created


        //ensure that it exists in the link
        getMockMvc().perform(get("/login").accept(TEXT_HTML))
            .andExpect(status().isOk())
            .andExpect(xpath("//a[text()='" + definition.getLinkText() + "']").exists());
    }

    @Test
    public void testThatDBFileUrlProvider() throws Exception {
        assertEquals(1, zoneAwareMetadataManager.getAvailableProviders().size());
        IdentityProvider provider = createSamlProvider("http://simplesamlphp.cfapps.io/saml2/idp/metadata.php");
        IdentityProviderDefinition definition = provider.getConfigValue(IdentityProviderDefinition.class);
        //ensure that the listener was not the one who created the provider
        assertEquals(1, zoneAwareMetadataManager.getAvailableProviders().size());

        //this simulates what the timer does
        zoneAwareMetadataManager.refreshAllProviders();

        //ensure that we have an actual SAML provider created
        assertEquals(2, zoneAwareMetadataManager.getAvailableProviders().size());

        //ensure that it exists in the link
        getMockMvc().perform(get("/login").accept(TEXT_HTML))
            .andExpect(status().isOk())
            .andExpect(xpath("//a[text()='" + definition.getLinkText() + "']").exists());

        provider.setActive(false);
        provider = providerProvisioning.update(provider);
        definition = provider.getConfigValue(IdentityProviderDefinition.class);

        //this simulates what the timer does
        zoneAwareMetadataManager.refreshAllProviders();

        //ensure that we have an actual SAML provider created
        assertEquals(1, zoneAwareMetadataManager.getAvailableProviders().size());

        //ensure that it exists in the link
        getMockMvc().perform(get("/login").accept(TEXT_HTML))
            .andExpect(status().isOk())
            .andExpect(xpath("//a[text()='" + definition.getLinkText() + "']").doesNotExist());
    }

    @Test
    public void testThatDifferentMetadataLocationsShowsOnLoginPage() throws Exception {
        assertEquals(1, zoneAwareMetadataManager.getAvailableProviders().size());
        IdentityProvider provider = createSamlProvider(IDP_META_DATA);
        IdentityProviderDefinition definition = provider.getConfigValue(IdentityProviderDefinition.class);
        //ensure that the listener was not the one who created the provider
        assertEquals(1, zoneAwareMetadataManager.getAvailableProviders().size());
        //this simulates what the timer does
        zoneAwareMetadataManager.refreshAllProviders();
        assertEquals(2, zoneAwareMetadataManager.getAvailableProviders().size());
        assertThat(zoneAwareMetadataManager.getAvailableProviders().get(1).getDelegate(), Matchers.instanceOf(ComparableProvider.class));
        assertThat(zoneAwareMetadataManager.getAvailableProviders().get(1).getDelegate(), Matchers.instanceOf(ConfigMetadataProvider.class));


        //ensure that it exists in the link
        getMockMvc().perform(get("/login").accept(TEXT_HTML))
            .andExpect(status().isOk())
            .andExpect(xpath("//a[text()='" + definition.getLinkText() + "']").exists());

        //change from XML content to a URL provider
        definition.setMetaDataLocation("http://simplesamlphp.cfapps.io/saml2/idp/metadata.php");
        provider.setConfig(JsonUtils.writeValueAsString(definition));
        providerProvisioning.update(provider);
        //this simulates what the timer does
        zoneAwareMetadataManager.refreshAllProviders();
        assertEquals(2, zoneAwareMetadataManager.getAvailableProviders().size());
        assertThat(zoneAwareMetadataManager.getAvailableProviders().get(1).getDelegate(), Matchers.instanceOf(ComparableProvider.class));
        assertThat(zoneAwareMetadataManager.getAvailableProviders().get(1).getDelegate(), Matchers.instanceOf(FixedHttpMetaDataProvider.class));

        //ensure that it exists in the link
        getMockMvc().perform(get("/login").accept(TEXT_HTML))
            .andExpect(status().isOk())
            .andExpect(xpath("//a[text()='" + definition.getLinkText() + "']").exists());

        //change from URL content to a  File provider
        definition.setMetaDataLocation(getMetadataFile(IDP_META_DATA).getAbsolutePath());
        provider.setConfig(JsonUtils.writeValueAsString(definition));
        providerProvisioning.update(provider);
        //this simulates what the timer does
        zoneAwareMetadataManager.refreshAllProviders();
        assertEquals(2, zoneAwareMetadataManager.getAvailableProviders().size());
        assertThat(zoneAwareMetadataManager.getAvailableProviders().get(1).getDelegate(), Matchers.instanceOf(ComparableProvider.class));
        assertThat(zoneAwareMetadataManager.getAvailableProviders().get(1).getDelegate(), Matchers.instanceOf(FilesystemMetadataProvider.class));

        //ensure that it exists in the link
        getMockMvc().perform(get("/login").accept(TEXT_HTML))
            .andExpect(status().isOk())
            .andExpect(xpath("//a[text()='" + definition.getLinkText() + "']").exists());
    }

    public File getMetadataFile(String metadata) throws Exception {
        File f = File.createTempFile("saml-metadata", ".xml");
        FileUtils.write(f, IDP_META_DATA);
        return f;
    }

    public IdentityProvider createSamlProvider(String metadata) {
        IdentityProviderDefinition definition = createSimplePHPSamlIDP(IdentityZone.getUaa().getId(), metadata);
        IdentityProvider provider = new IdentityProvider();
        provider.setActive(true);
        provider.setConfig(JsonUtils.writeValueAsString(definition));
        provider.setIdentityZoneId(IdentityZone.getUaa().getId());
        provider.setOriginKey(Origin.SAML);
        provider.setName("DB Added SAML Provider");
        provider.setType(Origin.SAML);
        provider = providerProvisioning.create(provider);
        return provider;
    }


    public IdentityProviderDefinition createSimplePHPSamlIDP(String zoneId, String metaData) {
        IdentityProviderDefinition def = new IdentityProviderDefinition();
        def.setZoneId(zoneId);
        def.setMetaDataLocation(metaData);
        def.setNameID("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");
        def.setAssertionConsumerIndex(0);
        def.setMetadataTrustCheck(false);
        def.setShowSamlLink(true);
        def.setIdpEntityAlias("simplesamlphp");
        def.setLinkText("Login with Simple SAML PHP");
        return def;
    }



}
