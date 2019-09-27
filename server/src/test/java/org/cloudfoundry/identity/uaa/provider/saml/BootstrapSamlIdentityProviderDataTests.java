/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.provider.saml;

import org.cloudfoundry.identity.uaa.impl.config.YamlMapFactoryBean;
import org.cloudfoundry.identity.uaa.impl.config.YamlProcessor;
import org.cloudfoundry.identity.uaa.provider.AbstractIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.junit.Before;
import org.junit.Test;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import java.util.*;

import static java.util.Arrays.asList;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.*;

public class BootstrapSamlIdentityProviderDataTests {

    public static final String testXmlFileData = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"http://www.okta.com/k2lvtem0VAJDMINKEYJW\"><md:IDPSSODescriptor WantAuthnRequestsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><md:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>MIICmTCCAgKgAwIBAgIGAUPATqmEMA0GCSqGSIb3DQEBBQUAMIGPMQswCQYDVQQGEwJVUzETMBEG\n" +
        "  A1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEU\n" +
        "  MBIGA1UECwwLU1NPUHJvdmlkZXIxEDAOBgNVBAMMB1Bpdm90YWwxHDAaBgkqhkiG9w0BCQEWDWlu\n" +
        "  Zm9Ab2t0YS5jb20wHhcNMTQwMTIzMTgxMjM3WhcNNDQwMTIzMTgxMzM3WjCBjzELMAkGA1UEBhMC\n" +
        "  VVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDTALBgNVBAoM\n" +
        "  BE9rdGExFDASBgNVBAsMC1NTT1Byb3ZpZGVyMRAwDgYDVQQDDAdQaXZvdGFsMRwwGgYJKoZIhvcN\n" +
        "  AQkBFg1pbmZvQG9rdGEuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCeil67/TLOiTZU\n" +
        "  WWgW2XEGgFZ94bVO90v5J1XmcHMwL8v5Z/8qjdZLpGdwI7Ph0CyXMMNklpaR/Ljb8fsls3amdT5O\n" +
        "  Bw92Zo8ulcpjw2wuezTwL0eC0wY/GQDAZiXL59npE6U+fH1lbJIq92hx0HJSru/0O1q3+A/+jjZL\n" +
        "  3tL/SwIDAQABMA0GCSqGSIb3DQEBBQUAA4GBAI5BoWZoH6Mz9vhypZPOJCEKa/K+biZQsA4Zqsuk\n" +
        "  vvphhSERhqk/Nv76Vkl8uvJwwHbQrR9KJx4L3PRkGCG24rix71jEuXVGZUsDNM3CUKnARx4MEab6\n" +
        "  GFHNkZ6DmoT/PFagngecHu+EwmuDtaG0rEkFrARwe+d8Ru0BN558abFb</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://pivotal.oktapreview.com/app/pivotal_pivotalcfdevelopment_1/k2lvtem0VAJDMINKEYJW/sso/saml\"/><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://pivotal.oktapreview.com/app/pivotal_pivotalcfdevelopment_1/k2lvtem0VAJDMINKEYJW/sso/saml\"/></md:IDPSSODescriptor></md:EntityDescriptor>";

    public static final String testXmlFileData2 = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!--\n" +
        "  ~ ******************************************************************************\n" +
        "  ~      Cloud Foundry\n" +
        "  ~      Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.\n" +
        "  ~      This product is licensed to you under the Apache License, Version 2.0 (the \"License\").\n" +
        "  ~      You may not use this product except in compliance with the License.\n" +
        "  ~\n" +
        "  ~      This product includes a number of subcomponents with\n" +
        "  ~      separate copyright notices and license terms. Your use of these\n" +
        "  ~      subcomponents is subject to the terms and conditions of the\n" +
        "  ~      subcomponent's license, as noted in the LICENSE file.\n" +
        "  ~ ******************************************************************************\n" +
        "  -->\n" +
        "\n" +
        "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"http://www.okta.com/k2lvtem0VAJDMINKEYJX\"><md:IDPSSODescriptor WantAuthnRequestsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><md:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>MIICmTCCAgKgAwIBAgIGAUPATqmEMA0GCSqGSIb3DQEBBQUAMIGPMQswCQYDVQQGEwJVUzETMBEG\n" +
        "  A1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEU\n" +
        "  MBIGA1UECwwLU1NPUHJvdmlkZXIxEDAOBgNVBAMMB1Bpdm90YWwxHDAaBgkqhkiG9w0BCQEWDWlu\n" +
        "  Zm9Ab2t0YS5jb20wHhcNMTQwMTIzMTgxMjM3WhcNNDQwMTIzMTgxMzM3WjCBjzELMAkGA1UEBhMC\n" +
        "  VVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDTALBgNVBAoM\n" +
        "  BE9rdGExFDASBgNVBAsMC1NTT1Byb3ZpZGVyMRAwDgYDVQQDDAdQaXZvdGFsMRwwGgYJKoZIhvcN\n" +
        "  AQkBFg1pbmZvQG9rdGEuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCeil67/TLOiTZU\n" +
        "  WWgW2XEGgFZ94bVO90v5J1XmcHMwL8v5Z/8qjdZLpGdwI7Ph0CyXMMNklpaR/Ljb8fsls3amdT5O\n" +
        "  Bw92Zo8ulcpjw2wuezTwL0eC0wY/GQDAZiXL59npE6U+fH1lbJIq92hx0HJSru/0O1q3+A/+jjZL\n" +
        "  3tL/SwIDAQABMA0GCSqGSIb3DQEBBQUAA4GBAI5BoWZoH6Mz9vhypZPOJCEKa/K+biZQsA4Zqsuk\n" +
        "  vvphhSERhqk/Nv76Vkl8uvJwwHbQrR9KJx4L3PRkGCG24rix71jEuXVGZUsDNM3CUKnARx4MEab6\n" +
        "  GFHNkZ6DmoT/PFagngecHu+EwmuDtaG0rEkFrARwe+d8Ru0BN558abFb</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://pivotal.oktapreview.com/app/pivotal_pivotalcfdevelopment_1/k2lvtem0VAJDMINKEYJW/sso/saml\"/><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://pivotal.oktapreview.com/app/pivotal_pivotalcfdevelopment_1/k2lvtem0VAJDMINKEYJW/sso/saml\"/></md:IDPSSODescriptor></md:EntityDescriptor>";

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

    BootstrapSamlIdentityProviderData bootstrap = null;
    SamlIdentityProviderDefinition singleAdd = null;
    public static final String singleAddAlias = "sample-alias";

    public static String sampleYaml = "  providers:\n" +
        "    okta-local:\n" +
        "      storeCustomAttributes: true\n" +
        "      idpMetadata: |\n" +
        "        " + testXmlFileData.replace("\n","\n        ") + "\n"+
        "      nameID: urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\n" +
        "      assertionConsumerIndex: 0\n" +
        "      metadataTrustCheck: true\n" +
        "      showSamlLoginLink: true\n" +
        "      linkText: 'Okta Preview 1'\n" +
        "      iconUrl: 'http://link.to/icon.jpg'\n" +
        "      "+ AbstractIdentityProviderDefinition.EMAIL_DOMAIN_ATTR+":\n" +
        "       - test.org\n" +
        "       - test.com\n" +
        "      externalGroupsWhitelist:\n" +
        "       - admin\n" +
        "       - user\n" +
        "      attributeMappings:\n" +
        "        given_name: first_name\n" +
        "        external_groups:\n" +
        "         - roles\n" +
        "    okta-local-2:\n" +
        "      idpMetadata: |\n" +
        "        <?xml version=\"1.0\" encoding=\"UTF-8\"?><md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"http://www.okta.com/k2lw4l5bPODCMIIDBRYZ\"><md:IDPSSODescriptor WantAuthnRequestsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><md:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>MIICmTCCAgKgAwIBAgIGAUPATqmEMA0GCSqGSIb3DQEBBQUAMIGPMQswCQYDVQQGEwJVUzETMBEG\n" +
        "        A1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEU\n" +
        "        MBIGA1UECwwLU1NPUHJvdmlkZXIxEDAOBgNVBAMMB1Bpdm90YWwxHDAaBgkqhkiG9w0BCQEWDWlu\n" +
        "        Zm9Ab2t0YS5jb20wHhcNMTQwMTIzMTgxMjM3WhcNNDQwMTIzMTgxMzM3WjCBjzELMAkGA1UEBhMC\n" +
        "        VVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDTALBgNVBAoM\n" +
        "        BE9rdGExFDASBgNVBAsMC1NTT1Byb3ZpZGVyMRAwDgYDVQQDDAdQaXZvdGFsMRwwGgYJKoZIhvcN\n" +
        "        AQkBFg1pbmZvQG9rdGEuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCeil67/TLOiTZU\n" +
        "        WWgW2XEGgFZ94bVO90v5J1XmcHMwL8v5Z/8qjdZLpGdwI7Ph0CyXMMNklpaR/Ljb8fsls3amdT5O\n" +
        "        Bw92Zo8ulcpjw2wuezTwL0eC0wY/GQDAZiXL59npE6U+fH1lbJIq92hx0HJSru/0O1q3+A/+jjZL\n" +
        "        3tL/SwIDAQABMA0GCSqGSIb3DQEBBQUAA4GBAI5BoWZoH6Mz9vhypZPOJCEKa/K+biZQsA4Zqsuk\n" +
        "        vvphhSERhqk/Nv76Vkl8uvJwwHbQrR9KJx4L3PRkGCG24rix71jEuXVGZUsDNM3CUKnARx4MEab6\n" +
        "        GFHNkZ6DmoT/PFagngecHu+EwmuDtaG0rEkFrARwe+d8Ru0BN558abFb</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://pivotal.oktapreview.com/app/pivotal_pivotalcfstaging_1/k2lw4l5bPODCMIIDBRYZ/sso/saml\"/><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://pivotal.oktapreview.com/app/pivotal_pivotalcfstaging_1/k2lw4l5bPODCMIIDBRYZ/sso/saml\"/></md:IDPSSODescriptor></md:EntityDescriptor>\n" +
        "      nameID: urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\n" +
        "      assertionConsumerIndex: 0\n" +
        "      metadataTrustCheck: true\n" +
        "      showSamlLoginLink: true\n" +
        "      linkText: 'Okta Preview 2'\n" +
        "    simplesamlphp-url:\n" +
        "      storeCustomAttributes: false\n" +
        "      assertionConsumerIndex: 0\n" +
        "      idpMetadata: http://simplesamlphp.com/saml2/idp/metadata.php\n" +
        "      metadataTrustCheck: false\n" +
        "      nameID: urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\n" +
        "    custom-authncontext:\n" +
        "      authnContext: [\"custom-context\", \"another-context\"]\n" +
        "      idpMetadata: |\n" +
        "        " + testXmlFileData.replace("\n","\n        ") + "\n"
        ;

    @Before
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
    }

    public static Map<String, Map<String, Object>> parseYaml(String sampleYaml) {
        YamlMapFactoryBean factory = new YamlMapFactoryBean();
        factory.setResolutionMethod(YamlProcessor.ResolutionMethod.OVERRIDE_AND_IGNORE);
        List<Resource> resources = new ArrayList<>();
        ByteArrayResource resource = new ByteArrayResource(sampleYaml.getBytes());
        resources.add(resource);
        factory.setResources(resources.toArray(new Resource[0]));
        Map<String, Object> tmpdata = factory.getObject();
        Map<String, Map<String, Object>> dataMap = new HashMap<>();
        for (Map.Entry<String, Object> entry : ((Map<String, Object>)tmpdata.get("providers")).entrySet()) {
            dataMap.put(entry.getKey(), (Map<String, Object>)entry.getValue());
        }
        return Collections.unmodifiableMap(dataMap);
    }

    private Map<String, Map<String, Object>> sampleData = parseYaml(sampleYaml);

    @Test
    public void testCloneIdentityProviderDefinition() {
        SamlIdentityProviderDefinition clone = singleAdd.clone();
        assertEquals(singleAdd, clone);
        assertNotSame(singleAdd, clone);
    }

    @Test
    public void testAddProviderDefinition() throws Exception {
        bootstrap.setIdentityProviders(sampleData);
        bootstrap.afterPropertiesSet();
        testGetIdentityProviderDefinitions(4, false);
        bootstrap.getSamlProviders()
            .forEach(p -> assertThat(p.isOverride(), is(true)));
    }

    @Test
    public void test_override() throws Exception {
        sampleData.get("okta-local").put("override", false);
        bootstrap.setIdentityProviders(sampleData);
        bootstrap.afterPropertiesSet();
        testGetIdentityProviderDefinitions(4, false);
        assertThat(
            bootstrap
                .getSamlProviders()
                .stream()
                .filter(p -> "okta-local".equals(p.getProvider().getOriginKey()))
                .findFirst()
                .get()
                .isOverride(),
            is(false)
        );
    }


    @Test
    public void testGetIdentityProviderDefinitions() throws Exception {
        testGetIdentityProviderDefinitions(4);
    }

    protected void testGetIdentityProviderDefinitions(int count) throws Exception {
        testGetIdentityProviderDefinitions(count, true);
    }
    protected void testGetIdentityProviderDefinitions(int count, boolean addData) {
        if (addData) {
            bootstrap.setIdentityProviders(sampleData);
            bootstrap.afterPropertiesSet();
        }
        List<SamlIdentityProviderDefinition> idps = bootstrap.getIdentityProviderDefinitions();
        assertEquals(count, idps.size());
        for (SamlIdentityProviderDefinition idp : idps) {
            switch (idp.getIdpEntityAlias()) {
                case "okta-local" : {
                    assertEquals(SamlIdentityProviderDefinition.MetadataLocation.DATA, idp.getType());
                    assertEquals(testXmlFileData.trim(), idp.getMetaDataLocation().trim());
                    assertEquals("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", idp.getNameID());
                    assertEquals(0, idp.getAssertionConsumerIndex());
                    assertEquals("Okta Preview 1", idp.getLinkText());
                    assertEquals("http://link.to/icon.jpg", idp.getIconUrl());
                    Map<String, Object> attributeMappings = new HashMap<>();
                    attributeMappings.put("given_name", "first_name");
                    attributeMappings.put("external_groups", Collections.singletonList("roles"));
                    assertEquals(attributeMappings, idp.getAttributeMappings());
                    assertEquals(asList("admin", "user"), idp.getExternalGroupsWhitelist());
                    assertTrue(idp.isShowSamlLink());
                    assertTrue(idp.isMetadataTrustCheck());
                    assertTrue(idp.getEmailDomain().containsAll(asList("test.com", "test.org")));
                    assertTrue(idp.isStoreCustomAttributes());
                    assertNull(idp.getAuthnContext());
                    break;
                }
                case "okta-local-2" : {
                    assertEquals(SamlIdentityProviderDefinition.MetadataLocation.DATA, idp.getType());
                    assertEquals("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", idp.getNameID());
                    assertEquals(0, idp.getAssertionConsumerIndex());
                    assertEquals("Okta Preview 2", idp.getLinkText());
                    assertNull(idp.getIconUrl());
                    assertTrue(idp.isShowSamlLink());
                    assertTrue(idp.isMetadataTrustCheck());
                    assertTrue(idp.isStoreCustomAttributes());
                    break;
                }
                case "okta-local-3" : {
                    assertEquals(SamlIdentityProviderDefinition.MetadataLocation.DATA, idp.getType());
                    assertEquals("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", idp.getNameID());
                    assertEquals(0, idp.getAssertionConsumerIndex());
                    assertEquals("Use your corporate credentials", idp.getLinkText());
                    assertNull(idp.getIconUrl());
                    assertTrue(idp.isShowSamlLink());
                    assertTrue(idp.isMetadataTrustCheck());
                    break;
                }
                case singleAddAlias : {
                    assertEquals(singleAdd, idp);
                    assertNotSame(singleAdd, idp);
                    break;
                }
                case "simplesamlphp-url" : {
                    assertTrue(idp.isShowSamlLink());
                    assertEquals("simplesamlphp-url", idp.getLinkText());
                    assertFalse(idp.isStoreCustomAttributes());
                    break;
                }
                case "custom-authncontext" : {
                    assertEquals(2, idp.getAuthnContext().size());
                    assertEquals("custom-context", idp.getAuthnContext().get(0));
                    assertEquals("another-context", idp.getAuthnContext().get(1));
                    break;
                }

                default:
                    fail();
            }
        }
    }

    @Test
    public void testGetIdentityProvidersWithLegacy_Valid_Provider() throws Exception {
        bootstrap.setLegacyIdpMetaData(testXmlFileData2);
        bootstrap.setLegacyIdpIdentityAlias("okta-local-3");
        bootstrap.setLegacyShowSamlLink(true);
        bootstrap.setLegacyNameId("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");
        testGetIdentityProviderDefinitions(5);
    }

    @Test
    public void testGetIdentityProviders() throws Exception {
        testGetIdentityProviderDefinitions(4);
    }

    @Test
    public void testCanParseASimpleSamlConfig() {
        String yaml = "  providers:\n" +
          "    my-okta:\n" +
          "      assertionConsumerIndex: 0\n" +
          "      emailDomain: \n" +
          "      - mydomain.io\n" +
          "      iconUrl: https://my.identityprovider.com/icon.png\n" +
          "      idpMetadata: https://pivotal.oktapreview.com/app/abcdefghasdfsafjdsklf/sso/saml/metadata\n" +
          "      linkText: Log in with Pivotal OktaPreview\n" +
          "      metadataTrustCheck: true\n" +
          "      nameID: urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\n" +
          "      showSamlLoginLink: false\n" +
          "      signMetaData: false\n" +
          "      signRequest: false\n" +
          "      skipSslValidation: false\n" +
          "      storeCustomAttributes: true";

        bootstrap.setIdentityProviders(parseYaml(yaml));
        bootstrap.afterPropertiesSet();
    }
    
    @Test
    public void testSetAddShadowUserOnLoginFromYaml() {
        String yaml = "  providers:\n" +
            "    provider-without-shadow-user-definition:\n" +
            "      storeCustomAttributes: true\n" +
            "      idpMetadata: |\n" +
            "        <?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
            "        <md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"provider1\">" +
            "        <md:IDPSSODescriptor WantAuthnRequestsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">" +
            "        <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>" +
            "        <md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://example.com\"/>" +
            "        </md:IDPSSODescriptor>" +
            "        </md:EntityDescriptor>\n" +
            "      nameID: urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\n" +
            "    provider-with-shadow-users-enabled:\n" +
            "      storeCustomAttributes: false\n" +
            "      idpMetadata: |\n" +
            "        <?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
            "        <md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"provider2\">" +
            "        <md:IDPSSODescriptor WantAuthnRequestsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">" +
            "        <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>" +
            "        <md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://example.com\"/>" +
            "        </md:IDPSSODescriptor>" +
            "        </md:EntityDescriptor>\n" +
            "      nameID: urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\n" +
            "      addShadowUserOnLogin: true\n" +
            "    provider-with-shadow-user-disabled:\n" +
            "      idpMetadata: |\n" +
            "        <?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
            "        <md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"provider3\">" +
            "        <md:IDPSSODescriptor WantAuthnRequestsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">" +
            "        <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>" +
            "        <md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://example.com\"/>" +
            "        </md:IDPSSODescriptor>" +
            "        </md:EntityDescriptor>\n" +
            "      nameID: urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\n" +
            "      addShadowUserOnLogin: false\n";

        bootstrap.setIdentityProviders(parseYaml(yaml));
        bootstrap.afterPropertiesSet();

        for (SamlIdentityProviderDefinition def : bootstrap.getIdentityProviderDefinitions()) {
            switch (def.getIdpEntityAlias()) {
                case "provider-without-shadow-user-definition" : {
                    assertTrue("If not specified, addShadowUserOnLogin is set to true", def.isAddShadowUserOnLogin());
                    assertTrue("Override store custom attributes to true", def.isStoreCustomAttributes());
                    break;
                }
                case "provider-with-shadow-users-enabled" : {
                    assertTrue("addShadowUserOnLogin can be set to true", def.isAddShadowUserOnLogin());
                    assertFalse("Default store custom attributes is false", def.isStoreCustomAttributes());
                    break;
                }
                case "provider-with-shadow-user-disabled" : {
                    assertFalse("addShadowUserOnLogin can be set to false", def.isAddShadowUserOnLogin());
                    assertTrue("Default store custom attributes is false", def.isStoreCustomAttributes());
                    break;
                }
                default: fail(String.format("Unknown provider %s", def.getIdpEntityAlias()));
            }

        }
    }
}
