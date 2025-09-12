/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.provider.saml;


import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.SlowHttpServer;
import org.junit.Rule;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.rules.ExpectedException;
import org.opensaml.DefaultBootstrap;
import org.opensaml.xml.parse.BasicParserPool;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.saml.trust.httpclient.TLSProtocolSocketFactory;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Timer;

import static java.time.Duration.ofSeconds;
import static java.util.Arrays.asList;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class SamlIdentityProviderConfiguratorTests {

    private Runnable stopHttpServer;
    private FixedHttpMetaDataProvider fixedHttpMetaDataProvider;
    private SlowHttpServer slowHttpServer;

    @BeforeAll
    public static void initializeOpenSAML() throws Exception {
        if (!org.apache.xml.security.Init.isInitialized()) {
            DefaultBootstrap.bootstrap();
        }
    }

    public static final String xmlWithoutID =
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?><md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"%s\"><md:IDPSSODescriptor WantAuthnRequestsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><md:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>MIICmTCCAgKgAwIBAgIGAUPATqmEMA0GCSqGSIb3DQEBBQUAMIGPMQswCQYDVQQGEwJVUzETMBEG\n" +
        "A1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEU\n" +
        "MBIGA1UECwwLU1NPUHJvdmlkZXIxEDAOBgNVBAMMB1Bpdm90YWwxHDAaBgkqhkiG9w0BCQEWDWlu\n" +
        "Zm9Ab2t0YS5jb20wHhcNMTQwMTIzMTgxMjM3WhcNNDQwMTIzMTgxMzM3WjCBjzELMAkGA1UEBhMC\n" +
        "VVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDTALBgNVBAoM\n" +
        "BE9rdGExFDASBgNVBAsMC1NTT1Byb3ZpZGVyMRAwDgYDVQQDDAdQaXZvdGFsMRwwGgYJKoZIhvcN\n" +
        "AQkBFg1pbmZvQG9rdGEuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCeil67/TLOiTZU\n" +
        "WWgW2XEGgFZ94bVO90v5J1XmcHMwL8v5Z/8qjdZLpGdwI7Ph0CyXMMNklpaR/Ljb8fsls3amdT5O\n" +
        "Bw92Zo8ulcpjw2wuezTwL0eC0wY/GQDAZiXL59npE6U+fH1lbJIq92hx0HJSru/0O1q3+A/+jjZL\n" +
        "3tL/SwIDAQABMA0GCSqGSIb3DQEBBQUAA4GBAI5BoWZoH6Mz9vhypZPOJCEKa/K+biZQsA4Zqsuk\n" +
        "vvphhSERhqk/Nv76Vkl8uvJwwHbQrR9KJx4L3PRkGCG24rix71jEuXVGZUsDNM3CUKnARx4MEab6\n" +
        "GFHNkZ6DmoT/PFagngecHu+EwmuDtaG0rEkFrARwe+d8Ru0BN558abFb</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://pivotal.oktapreview.com/app/pivotal_pivotalcfstaging_1/k2lw4l5bPODCMIIDBRYZ/sso/saml\"/><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://pivotal.oktapreview.com/app/pivotal_pivotalcfstaging_1/k2lw4l5bPODCMIIDBRYZ/sso/saml\"/></md:IDPSSODescriptor></md:EntityDescriptor>\n";

    private String getSimpleSamlPhpMetadata(String domain) {
        return "<?xml version=\"1.0\"?>\n" +
          "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" entityID=\"" + domain + "/saml2/idp/metadata.php\" ID=\"pfx214e4cdb-8fb2-592d-27a1-32ff06dcda69\"><ds:Signature>\n" +
          "  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
          "    <ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>\n" +
          "  <ds:Reference URI=\"#pfx214e4cdb-8fb2-592d-27a1-32ff06dcda69\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><ds:DigestValue>+sYzzLx/5TXtBZhC03uaQT0E/L8=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>gt9z/i8o16H0KQfV8+gCLgrBYOgaWsQe1Bon3G3UJQqc+z7YTNXl6rX69wbcQum/95KiLcF41BHoCeA4KZL75HE6mpXAF8NrPZiXlwwJFZe31HIfwmeu7JavuB/8QotWraM/u9DGtHVfDWFT92MPr18Odbvl62Gd2zA2PdZR3rz7DsrFc1QSB/Qz1VnQ+3Y8OUBRFDeZZUsNGRJ/l/GfYkiqmyV4fOak6bz0WeCSxY3tOl+F9X8r2gOHxOp3QRtRaK/UElRmPxnYC7UESI0Rq0AphHO6vRulA/EpSXTwu4qgZ6nDtGBOW/C+nQmg8zkv0QPvzk5IE2eaAAE3jkZq4w==</ds:SignatureValue>\n" +
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
          "    <md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"" + domain + "/saml2/idp/ SingleLogoutService.php\"/>\n" +
          "    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>\n" +
          "    <md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"" + domain + "/saml2/idp/SSOService.php\"/>\n" +
          "  </md:IDPSSODescriptor>\n" +
          "  <md:ContactPerson contactType=\"technical\">\n" +
          "    <md:GivenName>Filip</md:GivenName>\n" +
          "    <md:SurName>Hanik</md:SurName>\n" +
          "    <md:EmailAddress>fhanik@pivotal.io</md:EmailAddress>\n" +
          "  </md:ContactPerson>\n" +
          "</md:EntityDescriptor>\n";
    }

    public static final String xml = String.format(xmlWithoutID, "http://www.okta.com/k2lw4l5bPODCMIIDBRYZ");

    public static final String xmlWithoutHeader = xmlWithoutID.replace("<?xml version=\"1.0\" encoding=\"UTF-8\"?>", "");

    public static final String singleAddAlias = "sample-alias";

    private SamlIdentityProviderConfigurator configurator;
    private BootstrapSamlIdentityProviderData bootstrap;
    SamlIdentityProviderDefinition singleAdd = null;
    SamlIdentityProviderDefinition singleAddWithoutHeader = null;
    IdentityProviderProvisioning provisioning = mock(IdentityProviderProvisioning.class);
    RequestScopedIdpDefinitionsCache requestScopedIdpDefinitionsCache = mock(RequestScopedIdpDefinitionsCache.class);

    @BeforeEach
    public void setUp() {
        bootstrap = new BootstrapSamlIdentityProviderData();
        singleAdd = new SamlIdentityProviderDefinition()
                .setMetaDataLocation(String.format(BootstrapSamlIdentityProviderDataTests.xmlWithoutID, new RandomValueStringGenerator().generate()))
                .setIdpEntityAlias(singleAddAlias)
                .setNameID("sample-nameID")
                .setAssertionConsumerIndex(1)
                .setMetadataTrustCheck(true)
                .setLinkText("sample-link-test")
                .setIconUrl("sample-icon-url")
                .setZoneId("uaa");
        singleAddWithoutHeader = new SamlIdentityProviderDefinition()
                .setMetaDataLocation(String.format(xmlWithoutHeader, new RandomValueStringGenerator().generate()))
                .setIdpEntityAlias(singleAddAlias)
                .setNameID("sample-nameID")
                .setAssertionConsumerIndex(1)
                .setMetadataTrustCheck(true)
                .setLinkText("sample-link-test")
                .setIconUrl("sample-icon-url")
                .setZoneId("uaa");
        fixedHttpMetaDataProvider = mock(FixedHttpMetaDataProvider.class);

        configurator = new SamlIdentityProviderConfigurator(
            new BasicParserPool(), provisioning, fixedHttpMetaDataProvider, requestScopedIdpDefinitionsCache);

    }

    @Test
    public void testAddNullProvider() {
        Assertions.assertThrows(NullPointerException.class, () -> configurator.validateSamlIdentityProviderDefinition(null));
    }

    @Test
    public void testAddNullProviderAlias() {
        singleAdd.setIdpEntityAlias(null);

        Assertions.assertThrows(NullPointerException.class, () -> {
            configurator.validateSamlIdentityProviderDefinition(singleAdd);
        });
    }

    @Test
    public void testGetEntityID() throws Exception {

        Timer t = new Timer();
        bootstrap.setIdentityProviders(BootstrapSamlIdentityProviderDataTests.parseYaml(BootstrapSamlIdentityProviderDataTests.sampleYaml));
        bootstrap.afterPropertiesSet();
        for (SamlIdentityProviderDefinition def : bootstrap.getIdentityProviderDefinitions()) {
            switch (def.getIdpEntityAlias()) {
                case "okta-local": {
                    ComparableProvider provider = (ComparableProvider) configurator.getExtendedMetadataDelegateFromCache(def).getDelegate();
                    assertEquals("http://www.okta.com/k2lvtem0VAJDMINKEYJW", provider.getEntityID());
                    break;
                }
                case "okta-local-3": {
                    ComparableProvider provider = (ComparableProvider) configurator.getExtendedMetadataDelegateFromCache(def).getDelegate();
                    assertEquals("http://www.okta.com/k2lvtem0VAJDMINKEYJX", provider.getEntityID());
                    break;
                }
                case "okta-local-2": {
                    ComparableProvider provider = (ComparableProvider) configurator.getExtendedMetadataDelegateFromCache(def).getDelegate();
                    assertEquals("http://www.okta.com/k2lw4l5bPODCMIIDBRYZ", provider.getEntityID());
                    break;
                }
                case "simplesamlphp-url": {
                    when(fixedHttpMetaDataProvider.fetchMetadata(any(), anyBoolean())).thenReturn(getSimpleSamlPhpMetadata("http://simplesamlphp.somewhere.com").getBytes());
                    ComparableProvider provider = (ComparableProvider) configurator.getExtendedMetadataDelegateFromCache(def).getDelegate();
                    assertEquals("http://simplesamlphp.somewhere.com/saml2/idp/metadata.php", provider.getEntityID());
                    break;
                }
                case "custom-authncontext": {
                    ComparableProvider provider = (ComparableProvider) configurator.getExtendedMetadataDelegateFromCache(def).getDelegate();
                    assertEquals("http://www.okta.com/k2lvtem0VAJDMINKEYJW", provider.getEntityID());
                    break;
                }
                default:
                    fail(String.format("Unknown provider %s", def.getIdpEntityAlias()));
            }
        }
        t.cancel();
    }


    @Test
    public void testIdentityProviderDefinitionSocketFactoryTest() {
        singleAdd.setMetaDataLocation("http://www.test.org/saml/metadata");
        assertNull(singleAdd.getSocketFactoryClassName());
        singleAdd.setMetaDataLocation("https://www.test.org/saml/metadata");
        assertNull(singleAdd.getSocketFactoryClassName());
        singleAdd.setSocketFactoryClassName(TLSProtocolSocketFactory.class.getName());
        assertNull(singleAdd.getSocketFactoryClassName());
    }

    protected List<SamlIdentityProviderDefinition> getSamlIdentityProviderDefinitions(List<String> clientIdpAliases) {
        SamlIdentityProviderDefinition def1 = new SamlIdentityProviderDefinition()
          .setMetaDataLocation(xml)
          .setIdpEntityAlias("simplesamlphp-url")
          .setNameID("sample-nameID")
          .setAssertionConsumerIndex(1)
          .setMetadataTrustCheck(true)
          .setLinkText("sample-link-test")
          .setIconUrl("sample-icon-url")
          .setZoneId("other-zone-id");
        IdentityProvider idp1 = mock(IdentityProvider.class);
        when(idp1.getType()).thenReturn(OriginKeys.SAML);
        when(idp1.getConfig()).thenReturn(def1);

        IdentityProvider idp2 = mock(IdentityProvider.class);
        when(idp2.getType()).thenReturn(OriginKeys.SAML);
        when(idp2.getConfig()).thenReturn(def1.clone().setIdpEntityAlias("okta-local-2"));

        IdentityProvider idp3 = mock(IdentityProvider.class);
        when(idp3.getType()).thenReturn(OriginKeys.SAML);
        when(idp3.getConfig()).thenReturn(def1.clone().setIdpEntityAlias("okta-local-3"));

        when(provisioning.retrieveActive(anyString())).thenReturn(Arrays.asList(idp1, idp2));

        return configurator.getIdentityProviderDefinitions(clientIdpAliases, Arrays.asList(idp1, idp2));
    }

    @Test
    public void testGetIdentityProviderDefinititonsForAllowedProviders() {
        List<String> clientIdpAliases = asList("simplesamlphp-url", "okta-local-2");
        List<SamlIdentityProviderDefinition> clientIdps = getSamlIdentityProviderDefinitions(clientIdpAliases);
        assertEquals(2, clientIdps.size());
        assertTrue(clientIdpAliases.contains(clientIdps.get(0).getIdpEntityAlias()));
        assertTrue(clientIdpAliases.contains(clientIdps.get(1).getIdpEntityAlias()));
    }

    @Test
    public void testReturnNoIdpsInZoneForClientWithNoAllowedProviders() {
        List<String> clientIdpAliases = Collections.singletonList("non-existent");
        List<SamlIdentityProviderDefinition> clientIdps = getSamlIdentityProviderDefinitions(clientIdpAliases);
        assertEquals(0, clientIdps.size());
    }

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @BeforeEach
    public void setupHttp() {
        slowHttpServer = new SlowHttpServer();
    }

    @AfterEach
    public void stopHttp() {
        slowHttpServer.stop();
    }

    @Test
    public void shouldTimeoutWhenFetchingMetadataURL() {
        slowHttpServer.run();

        expectedException.expect(NullPointerException.class);

        SamlIdentityProviderDefinition def = new SamlIdentityProviderDefinition();
        def.setMetaDataLocation("https://localhost:23439");
        def.setSkipSslValidation(true);

        Assertions.assertTimeout(ofSeconds(1), () -> {
            Assertions.assertThrows(NullPointerException.class, () -> configurator.configureURLMetadata(def));
        });
    }
}
