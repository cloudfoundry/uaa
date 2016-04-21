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

import org.apache.commons.httpclient.params.HttpClientParams;
import org.cloudfoundry.identity.uaa.provider.AbstractIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.impl.config.YamlMapFactoryBean;
import org.cloudfoundry.identity.uaa.impl.config.YamlProcessor;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.parse.BasicParserPool;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate;
import org.springframework.security.saml.trust.httpclient.TLSProtocolSocketFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Timer;
import java.util.UUID;

import static java.util.Arrays.asList;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class IdentityProviderConfiguratorTests {

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

    SamlIdentityProviderConfigurator conf = null;
    SamlIdentityProviderDefinition singleAdd = null;
    SamlIdentityProviderDefinition singleAddWithoutHeader = null;
    private static final String singleAddAlias = "sample-alias";

    public static String sampleYaml = "  providers:\n" +
        "    okta-local:\n" +
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
        "    vsphere.local:\n" +
        "      idpMetadata: https://win2012-sso2.localdomain:7444/websso/SAML2/Metadata/vsphere.local\n" +
        "      nameID: urn:oasis:names:tc:SAML:2.0:nameid-format:persistent\n" +
        "      assertionConsumerIndex: 1\n" +
        "      metadataTrustCheck: false\n"+
        "      showSamlLoginLink: false\n" +
        "      linkText: 'Log in with vCenter SSO'\n" +
        "      iconUrl: 'http://vsphere.local/iconurl.jpg'\n" +
        "    simplesamlphp-url:\n" +
        "      assertionConsumerIndex: 0\n" +
        "      idpMetadata: http://simplesamlphp.identity.cf-app.com/saml2/idp/metadata.php\n" +
        "      metadataTrustCheck: false\n" +
        "      nameID: urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\n" +
        "    incomplete-provider:\n" +
        "      idpMetadata: http://localhost:8081/openam/saml2/jsp/exportmetadata.jsp?entityid=http://localhost:8081/openam\n";

    @Before
    public void setUp() throws Exception {
        conf = new SamlIdentityProviderConfigurator();
        conf.setParserPool(new BasicParserPool());
        singleAdd = new SamlIdentityProviderDefinition()
            .setMetaDataLocation(String.format(xmlWithoutID, new RandomValueStringGenerator().generate()))
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
    }

    private static Map<String, Map<String, Object>> parseYaml(String sampleYaml) {
        YamlMapFactoryBean factory = new YamlMapFactoryBean();
        factory.setResolutionMethod(YamlProcessor.ResolutionMethod.OVERRIDE_AND_IGNORE);
        List<Resource> resources = new ArrayList<>();
        ByteArrayResource resource = new ByteArrayResource(sampleYaml.getBytes());
        resources.add(resource);
        factory.setResources(resources.toArray(new Resource[resources.size()]));
        Map<String, Object> tmpdata = factory.getObject();
        Map<String, Map<String, Object>> dataMap = new HashMap<>();
        for (Map.Entry<String, Object> entry : ((Map<String, Object>)tmpdata.get("providers")).entrySet()) {
            dataMap.put(entry.getKey(), (Map<String, Object>)entry.getValue());
        }
        return Collections.unmodifiableMap(dataMap);
    }

    private Map<String, Map<String, Object>> sampleData = parseYaml(sampleYaml);

    @Test
    public void testCloneIdentityProviderDefinition() throws Exception {
        SamlIdentityProviderDefinition clone = singleAdd.clone();
        assertEquals(singleAdd, clone);
        assertNotSame(singleAdd, clone);
    }

    @Test
    public void testSingleAddProviderDefinition() throws Exception {
        conf.setIdentityProviders(sampleData);
        conf.afterPropertiesSet();
        conf.addSamlIdentityProviderDefinition(singleAdd);
        testGetIdentityProviderDefinitions(4, false);
    }

    @Test
    public void testSingleAddProviderWithoutXMLHeader() throws Exception {
        conf.setIdentityProviders(sampleData);
        conf.afterPropertiesSet();
        conf.addSamlIdentityProviderDefinition(singleAddWithoutHeader);
        testGetIdentityProviderDefinitions(4, false);
    }

    @Test(expected = NullPointerException.class)
    public void testAddNullProvider() throws Exception {
        conf.addSamlIdentityProviderDefinition(null);
    }

    @Test(expected = NullPointerException.class)
    public void testAddNullProviderAlias() throws Exception {
        singleAdd.setIdpEntityAlias(null);
        conf.addSamlIdentityProviderDefinition(singleAdd);
    }

    @Test
    public void testGetEntityID() throws Exception {
        Timer t = new Timer();
        conf.setIdentityProviders(sampleData);
        conf.afterPropertiesSet();
        for (SamlIdentityProviderDefinition def : conf.getIdentityProviderDefinitions()) {
            switch (def.getIdpEntityAlias()) {
                case "okta-local" : {
                    ComparableProvider provider = (ComparableProvider)conf.getExtendedMetadataDelegateFromCache(def).getDelegate();
                    assertEquals("http://www.okta.com/k2lvtem0VAJDMINKEYJW", provider.getEntityID());
                    break;
                }
                case "okta-local-3" : {
                    ComparableProvider provider = (ComparableProvider)conf.getExtendedMetadataDelegateFromCache(def).getDelegate();
                    assertEquals("http://www.okta.com/k2lvtem0VAJDMINKEYJX", provider.getEntityID());
                    break;
                }
                case "okta-local-2" : {
                    ComparableProvider provider = (ComparableProvider)conf.getExtendedMetadataDelegateFromCache(def).getDelegate();
                    assertEquals("http://www.okta.com/k2lw4l5bPODCMIIDBRYZ", provider.getEntityID());
                    break;
                }
                case "simplesamlphp-url" : {
                    ComparableProvider provider = (ComparableProvider)conf.getExtendedMetadataDelegateFromCache(def).getDelegate();
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
        assertEquals(SamlIdentityProviderDefinition.DEFAULT_HTTP_SOCKET_FACTORY, singleAdd.getSocketFactoryClassName());
        singleAdd.setMetaDataLocation("https://www.test.org/saml/metadata");
        assertEquals(SamlIdentityProviderDefinition.DEFAULT_HTTPS_SOCKET_FACTORY, singleAdd.getSocketFactoryClassName());
        singleAdd.setSocketFactoryClassName(TLSProtocolSocketFactory.class.getName());
        assertEquals(TLSProtocolSocketFactory.class.getName(), singleAdd.getSocketFactoryClassName());
    }

    @Test
    public void testGetIdentityProviderDefinitionsForZone() throws Exception {
        String zoneId = UUID.randomUUID().toString();
        IdentityZone zone = MultitenancyFixture.identityZone(zoneId, "test-zone");

        SamlIdentityProviderDefinition samlIdentityProviderDefinition = new SamlIdentityProviderDefinition()
            .setMetaDataLocation(xml)
            .setIdpEntityAlias("zoneIdpAlias")
            .setNameID("sample-nameID")
            .setAssertionConsumerIndex(1)
            .setMetadataTrustCheck(true)
            .setLinkText("sample-link-test")
            .setIconUrl("sample-icon-url")
            .setZoneId(zoneId);
        conf.addSamlIdentityProviderDefinition(samlIdentityProviderDefinition);

        List<SamlIdentityProviderDefinition> idps = conf.getIdentityProviderDefinitionsForZone(zone);
        assertEquals(1, idps.size());
        assertEquals("zoneIdpAlias", idps.get(0).getIdpEntityAlias());
    }

    @Test
    public void testGetIdentityProviderDefinititonsForAllowedProviders() throws Exception {
        BaseClientDetails clientDetails = new BaseClientDetails();
        List<String> clientIdpAliases = asList("simplesamlphp-url", "okta-local-2");
        clientDetails.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, clientIdpAliases);

        conf.setIdentityProviders(sampleData);
        conf.afterPropertiesSet();
        List<SamlIdentityProviderDefinition> clientIdps = conf.getIdentityProviderDefinitions(clientIdpAliases, IdentityZoneHolder.get());
        assertEquals(2, clientIdps.size());
        assertTrue(clientIdpAliases.contains(clientIdps.get(0).getIdpEntityAlias()));
        assertTrue(clientIdpAliases.contains(clientIdps.get(1).getIdpEntityAlias()));
    }

    @Test
    public void testReturnAllIdpsInZoneForClientWithNoAllowedProviders() throws Exception {
        conf.setIdentityProviders(sampleData);
        conf.afterPropertiesSet();
        SamlIdentityProviderDefinition samlIdentityProviderDefinitionInOtherZone = new SamlIdentityProviderDefinition()
            .setMetaDataLocation(xml)
            .setIdpEntityAlias("zoneIdpAlias")
            .setNameID("sample-nameID")
            .setAssertionConsumerIndex(1)
            .setMetadataTrustCheck(true)
            .setLinkText("sample-link-test")
            .setIconUrl("sample-icon-url")
            .setZoneId("other-zone-id");
        try {
            conf.addSamlIdentityProviderDefinition(samlIdentityProviderDefinitionInOtherZone);
        } catch (MetadataProviderException e) {
        }

        List<SamlIdentityProviderDefinition> clientIdps = conf.getIdentityProviderDefinitions(null, IdentityZoneHolder.get());
        assertEquals(3, clientIdps.size());
    }

    @Test
    public void testReturnNoIdpsInZoneForClientWithNoAllowedProviders() throws Exception {
        conf.setIdentityProviders(sampleData);
        conf.afterPropertiesSet();
        String xmlMetadata = String.format(xmlWithoutID, new RandomValueStringGenerator().generate());
        SamlIdentityProviderDefinition samlIdentityProviderDefinitionInOtherZone = new SamlIdentityProviderDefinition()
            .setMetaDataLocation(xmlMetadata)
            .setIdpEntityAlias("zoneIdpAlias")
            .setNameID("sample-nameID")
            .setAssertionConsumerIndex(1)
            .setMetadataTrustCheck(true)
            .setLinkText("sample-link-test")
            .setIconUrl("sample-icon-url")
            .setZoneId("other-zone-id");
        conf.addSamlIdentityProviderDefinition(samlIdentityProviderDefinitionInOtherZone);

        List<SamlIdentityProviderDefinition> clientIdps = conf.getIdentityProviderDefinitions(null, IdentityZoneHolder.get());
        assertFalse(clientIdps.isEmpty());
    }

    @Test
    public void testGetIdentityProviderDefinitions() throws Exception {
        testGetIdentityProviderDefinitions(3);
    }

    protected void testGetIdentityProviderDefinitions(int count) throws Exception {
        testGetIdentityProviderDefinitions(count, true);
    }
    protected void testGetIdentityProviderDefinitions(int count, boolean addData) throws Exception {
        if (addData) {
            conf.setIdentityProviders(sampleData);
            conf.afterPropertiesSet();
        }
        List<SamlIdentityProviderDefinition> idps = conf.getIdentityProviderDefinitions();
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
                    attributeMappings.put("external_groups", asList("roles"));
                    assertEquals(attributeMappings, idp.getAttributeMappings());
                    assertEquals(asList("admin", "user"), idp.getExternalGroupsWhitelist());
                    assertTrue(idp.isShowSamlLink());
                    assertTrue(idp.isMetadataTrustCheck());
                    assertTrue(idp.getEmailDomain().containsAll(asList("test.com", "test.org")));
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
                    break;
                }
                default:
                    fail();
            }
        }
    }

    @Test
    public void testGetIdentityProvidersWithLegacy_Invalid_Provider() throws Exception {
        conf.setLegacyIdpMetaData("http://win2012-sso2.localdomain:7444/websso/SAML2/Metadata/vsphere.local");
        conf.setLegacyIdpIdentityAlias("vsphere.local.legacy");
        conf.setLegacyNameId("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");
        testGetIdentityProviderDefinitions(3);
    }

    @Test
    public void testGetIdentityProvidersWithLegacy_Valid_Provider() throws Exception {
        conf.setLegacyIdpMetaData(testXmlFileData2);
        conf.setLegacyIdpIdentityAlias("okta-local-3");
        conf.setLegacyShowSamlLink(true);
        conf.setLegacyNameId("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");
        testGetIdentityProviderDefinitions(4);
    }

    @Test
    public void testGetIdentityProviders() throws Exception {
        conf.setClientParams(new HttpClientParams());
        testGetIdentityProviderDefinitions(3);
        conf.getSamlIdentityProviders();
    }


    @Test(expected = IllegalStateException.class)
    public void testDuplicateAlias_In_LegacyConfig() throws Exception {
        conf.setLegacyIdpMetaData("https://simplesamlphp.identity.cf-app.com/saml2/idp/metadata.php");
        conf.setLegacyIdpIdentityAlias("simplesamlphp-url");
        conf.setIdentityProviders(sampleData);
        conf.afterPropertiesSet();
    }

    @Test
    public void testDuplicate_EntityID_IsRejected() throws Exception {
        conf.setIdentityProviders(sampleData);
        conf.afterPropertiesSet();
        testGetIdentityProviderDefinitions(3, false);

        SamlIdentityProviderDefinition def = new SamlIdentityProviderDefinition()
            .setMetaDataLocation("http://simplesamlphp.identity.cf-app.com/saml2/idp/metadata.php")
            .setIdpEntityAlias("simplesamlphp-url-2")
            .setNameID("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
            .setZoneId(IdentityZone.getUaa().getId())
            .setShowSamlLink(true);

        //duplicate entityID - different alias
        ExtendedMetadataDelegate[] delegate = null;
        try {
            delegate = conf.addSamlIdentityProviderDefinition(def);
            fail("Duplicate entity ID should not succeed");
        }catch (MetadataProviderException x) {}
        testGetIdentityProviderDefinitions(3, false);
        assertNull(delegate);

        //duplicate entityID - same alias
        def.setIdpEntityAlias("simplesamlphp-url");
        delegate = conf.addSamlIdentityProviderDefinition(def);
        testGetIdentityProviderDefinitions(3, false);
        assertNotNull(delegate);
        assertNotNull(delegate[0]);
        assertNotNull(delegate[1]);

    }

    @Test
    public void testSetAddShadowUserOnLoginFromYaml() throws Exception {
        String yaml = "  providers:\n" +
            "    provider-without-shadow-user-definition:\n" +
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

        conf.setIdentityProviders(parseYaml(yaml));
        conf.afterPropertiesSet();

        for (SamlIdentityProviderDefinition def : conf.getIdentityProviderDefinitions()) {
            switch (def.getIdpEntityAlias()) {
                case "provider-without-shadow-user-definition" : {
                    assertTrue("If not specified, addShadowUserOnLogin is set to true", def.isAddShadowUserOnLogin());
                    break;
                }
                case "provider-with-shadow-users-enabled" : {
                    assertTrue("addShadowUserOnLogin can be set to true", def.isAddShadowUserOnLogin());
                    break;
                }
                case "provider-with-shadow-user-disabled" : {
                    assertFalse("addShadowUserOnLogin can be set to false", def.isAddShadowUserOnLogin());
                    break;
                }
                default: fail(String.format("Unknown provider %s", def.getIdpEntityAlias()));
            }

        }
    }
}
