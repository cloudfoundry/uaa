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


import org.cloudfoundry.identity.uaa.cache.ExpiringUrlCache;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.util.TimeServiceImpl;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;
import org.opensaml.DefaultBootstrap;
import org.opensaml.xml.parse.BasicParserPool;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate;
import org.springframework.security.saml.trust.httpclient.TLSProtocolSocketFactory;

import java.util.Arrays;
import java.util.List;
import java.util.Timer;

import static java.util.Arrays.asList;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class SamlIdentityProviderConfiguratorTests {
    @BeforeClass
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

    public static final String xml = String.format(xmlWithoutID, "http://www.okta.com/k2lw4l5bPODCMIIDBRYZ");

    public static final String xmlWithoutHeader = xmlWithoutID.replace("<?xml version=\"1.0\" encoding=\"UTF-8\"?>", "");

    public static final String singleAddAlias = "sample-alias";

    private SamlIdentityProviderConfigurator configurator;
    private BootstrapSamlIdentityProviderConfigurator bootstrap;
    SamlIdentityProviderDefinition singleAdd = null;
    SamlIdentityProviderDefinition singleAddWithoutHeader = null;
    IdentityProviderProvisioning provisioning = mock(IdentityProviderProvisioning.class);

    @Before
    public void setUp() throws Exception {
        bootstrap = new BootstrapSamlIdentityProviderConfigurator();
        configurator = new SamlIdentityProviderConfigurator();
        configurator.setParserPool(new BasicParserPool());
        singleAdd = new SamlIdentityProviderDefinition()
            .setMetaDataLocation(String.format(BootstrapSamlIdentityProviderConfiguratorTests.xmlWithoutID, new RandomValueStringGenerator().generate()))
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
        configurator.setIdentityProviderProvisioning(provisioning);
        configurator.setContentCache(new ExpiringUrlCache(1000*60*10, new TimeServiceImpl(), 100));
    }

    /*@Test
    @Ignore
    public void testSingleAddProviderWithoutXMLHeader() throws Exception {
        ExtendedMetadataDelegate[] result = configurator.validateSamlIdentityProviderDefinition(singleAddWithoutHeader);
        assertNotNull(result);
        assertEquals(2, result.length);
        assertNotNull(result[0]);
        assertNull(result[1]);
    }*/

    @Test(expected = NullPointerException.class)
    public void testAddNullProvider() throws Exception {
        configurator.validateSamlIdentityProviderDefinition(null);
    }

    @Test(expected = NullPointerException.class)
    public void testAddNullProviderAlias() throws Exception {
        singleAdd.setIdpEntityAlias(null);
        configurator.validateSamlIdentityProviderDefinition(singleAdd);
    }

    @Test
    public void testGetEntityID() throws Exception {
        Timer t = new Timer();
        bootstrap.setIdentityProviders(BootstrapSamlIdentityProviderConfiguratorTests.parseYaml(BootstrapSamlIdentityProviderConfiguratorTests.sampleYaml));
        bootstrap.afterPropertiesSet();
        for (SamlIdentityProviderDefinition def : bootstrap.getIdentityProviderDefinitions()) {
            switch (def.getIdpEntityAlias()) {
                case "okta-local" : {
                    ComparableProvider provider = (ComparableProvider) configurator.getExtendedMetadataDelegateFromCache(def).getDelegate();
                    assertEquals("http://www.okta.com/k2lvtem0VAJDMINKEYJW", provider.getEntityID());
                    break;
                }
                case "okta-local-3" : {
                    ComparableProvider provider = (ComparableProvider) configurator.getExtendedMetadataDelegateFromCache(def).getDelegate();
                    assertEquals("http://www.okta.com/k2lvtem0VAJDMINKEYJX", provider.getEntityID());
                    break;
                }
                case "okta-local-2" : {
                    ComparableProvider provider = (ComparableProvider) configurator.getExtendedMetadataDelegateFromCache(def).getDelegate();
                    assertEquals("http://www.okta.com/k2lw4l5bPODCMIIDBRYZ", provider.getEntityID());
                    break;
                }
                case "simplesamlphp-url" : {
                    ComparableProvider provider = (ComparableProvider) configurator.getExtendedMetadataDelegateFromCache(def).getDelegate();
                    assertEquals("http://simplesamlphp.identity.cf-app.com/saml2/idp/metadata.php", provider.getEntityID());
                    break;
                }
                default: fail(String.format("Unknown provider %s", def.getIdpEntityAlias()));
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

    protected List<SamlIdentityProviderDefinition> getSamlIdentityProviderDefinitions(List<String> clientIdpAliases ) {
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

        return configurator.getIdentityProviderDefinitions(clientIdpAliases, IdentityZoneHolder.get());
    }

    @Test
    public void testGetIdentityProviderDefinititonsForAllowedProviders() throws Exception {
        List<String> clientIdpAliases = asList("simplesamlphp-url", "okta-local-2");
        List<SamlIdentityProviderDefinition> clientIdps = getSamlIdentityProviderDefinitions(clientIdpAliases);
        assertEquals(2, clientIdps.size());
        assertTrue(clientIdpAliases.contains(clientIdps.get(0).getIdpEntityAlias()));
        assertTrue(clientIdpAliases.contains(clientIdps.get(1).getIdpEntityAlias()));
    }


    @Test
    public void testReturnNoIdpsInZoneForClientWithNoAllowedProviders() throws Exception {
        List<String> clientIdpAliases = asList("non-existent");
        List<SamlIdentityProviderDefinition> clientIdps = getSamlIdentityProviderDefinitions(clientIdpAliases);
        assertEquals(0, clientIdps.size());
    }
}