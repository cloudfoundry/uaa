/*
 * *****************************************************************************
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

import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.provider.AbstractIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManagerImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.config.YamlMapFactoryBean;
import org.springframework.beans.factory.config.YamlProcessor;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static java.util.Arrays.asList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.fail;
import static org.mockito.Mockito.mock;

public class BootstrapSamlIdentityProviderDataTests {

    private static final String TEST_XML_FILE_DATA = """
            <?xml version="1.0" encoding="UTF-8"?><md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="http://www.okta.com/k2lvtem0VAJDMINKEYJW"><md:IDPSSODescriptor WantAuthnRequestsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>MIICmTCCAgKgAwIBAgIGAUPATqmEMA0GCSqGSIb3DQEBBQUAMIGPMQswCQYDVQQGEwJVUzETMBEG
              A1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEU
              MBIGA1UECwwLU1NPUHJvdmlkZXIxEDAOBgNVBAMMB1Bpdm90YWwxHDAaBgkqhkiG9w0BCQEWDWlu
              Zm9Ab2t0YS5jb20wHhcNMTQwMTIzMTgxMjM3WhcNNDQwMTIzMTgxMzM3WjCBjzELMAkGA1UEBhMC
              VVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDTALBgNVBAoM
              BE9rdGExFDASBgNVBAsMC1NTT1Byb3ZpZGVyMRAwDgYDVQQDDAdQaXZvdGFsMRwwGgYJKoZIhvcN
              AQkBFg1pbmZvQG9rdGEuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCeil67/TLOiTZU
              WWgW2XEGgFZ94bVO90v5J1XmcHMwL8v5Z/8qjdZLpGdwI7Ph0CyXMMNklpaR/Ljb8fsls3amdT5O
              Bw92Zo8ulcpjw2wuezTwL0eC0wY/GQDAZiXL59npE6U+fH1lbJIq92hx0HJSru/0O1q3+A/+jjZL
              3tL/SwIDAQABMA0GCSqGSIb3DQEBBQUAA4GBAI5BoWZoH6Mz9vhypZPOJCEKa/K+biZQsA4Zqsuk
              vvphhSERhqk/Nv76Vkl8uvJwwHbQrR9KJx4L3PRkGCG24rix71jEuXVGZUsDNM3CUKnARx4MEab6
              GFHNkZ6DmoT/PFagngecHu+EwmuDtaG0rEkFrARwe+d8Ru0BN558abFb</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://pivotal.oktapreview.com/app/pivotal_pivotalcfdevelopment_1/k2lvtem0VAJDMINKEYJW/sso/saml"/><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://pivotal.oktapreview.com/app/pivotal_pivotalcfdevelopment_1/k2lvtem0VAJDMINKEYJW/sso/saml"/></md:IDPSSODescriptor></md:EntityDescriptor>""";

    private static final String TEST_XML_FILE_DATA_2 = """
            <?xml version="1.0" encoding="UTF-8"?><!--
              ~ ******************************************************************************
              ~      Cloud Foundry
              ~      Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
              ~      This product is licensed to you under the Apache License, Version 2.0 (the "License").
              ~      You may not use this product except in compliance with the License.
              ~
              ~      This product includes a number of subcomponents with
              ~      separate copyright notices and license terms. Your use of these
              ~      subcomponents is subject to the terms and conditions of the
              ~      subcomponent's license, as noted in the LICENSE file.
              ~ ******************************************************************************
              -->
            
            <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="http://www.okta.com/k2lvtem0VAJDMINKEYJX"><md:IDPSSODescriptor WantAuthnRequestsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>MIICmTCCAgKgAwIBAgIGAUPATqmEMA0GCSqGSIb3DQEBBQUAMIGPMQswCQYDVQQGEwJVUzETMBEG
              A1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEU
              MBIGA1UECwwLU1NPUHJvdmlkZXIxEDAOBgNVBAMMB1Bpdm90YWwxHDAaBgkqhkiG9w0BCQEWDWlu
              Zm9Ab2t0YS5jb20wHhcNMTQwMTIzMTgxMjM3WhcNNDQwMTIzMTgxMzM3WjCBjzELMAkGA1UEBhMC
              VVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDTALBgNVBAoM
              BE9rdGExFDASBgNVBAsMC1NTT1Byb3ZpZGVyMRAwDgYDVQQDDAdQaXZvdGFsMRwwGgYJKoZIhvcN
              AQkBFg1pbmZvQG9rdGEuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCeil67/TLOiTZU
              WWgW2XEGgFZ94bVO90v5J1XmcHMwL8v5Z/8qjdZLpGdwI7Ph0CyXMMNklpaR/Ljb8fsls3amdT5O
              Bw92Zo8ulcpjw2wuezTwL0eC0wY/GQDAZiXL59npE6U+fH1lbJIq92hx0HJSru/0O1q3+A/+jjZL
              3tL/SwIDAQABMA0GCSqGSIb3DQEBBQUAA4GBAI5BoWZoH6Mz9vhypZPOJCEKa/K+biZQsA4Zqsuk
              vvphhSERhqk/Nv76Vkl8uvJwwHbQrR9KJx4L3PRkGCG24rix71jEuXVGZUsDNM3CUKnARx4MEab6
              GFHNkZ6DmoT/PFagngecHu+EwmuDtaG0rEkFrARwe+d8Ru0BN558abFb</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://pivotal.oktapreview.com/app/pivotal_pivotalcfdevelopment_1/k2lvtem0VAJDMINKEYJW/sso/saml"/><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://pivotal.oktapreview.com/app/pivotal_pivotalcfdevelopment_1/k2lvtem0VAJDMINKEYJW/sso/saml"/></md:IDPSSODescriptor></md:EntityDescriptor>""";

    public static final String XML_WITHOUT_ID = """
            <?xml version="1.0" encoding="UTF-8"?><md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="%s"><md:IDPSSODescriptor WantAuthnRequestsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>MIICmTCCAgKgAwIBAgIGAUPATqmEMA0GCSqGSIb3DQEBBQUAMIGPMQswCQYDVQQGEwJVUzETMBEG
            A1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEU
            MBIGA1UECwwLU1NPUHJvdmlkZXIxEDAOBgNVBAMMB1Bpdm90YWwxHDAaBgkqhkiG9w0BCQEWDWlu
            Zm9Ab2t0YS5jb20wHhcNMTQwMTIzMTgxMjM3WhcNNDQwMTIzMTgxMzM3WjCBjzELMAkGA1UEBhMC
            VVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDTALBgNVBAoM
            BE9rdGExFDASBgNVBAsMC1NTT1Byb3ZpZGVyMRAwDgYDVQQDDAdQaXZvdGFsMRwwGgYJKoZIhvcN
            AQkBFg1pbmZvQG9rdGEuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCeil67/TLOiTZU
            WWgW2XEGgFZ94bVO90v5J1XmcHMwL8v5Z/8qjdZLpGdwI7Ph0CyXMMNklpaR/Ljb8fsls3amdT5O
            Bw92Zo8ulcpjw2wuezTwL0eC0wY/GQDAZiXL59npE6U+fH1lbJIq92hx0HJSru/0O1q3+A/+jjZL
            3tL/SwIDAQABMA0GCSqGSIb3DQEBBQUAA4GBAI5BoWZoH6Mz9vhypZPOJCEKa/K+biZQsA4Zqsuk
            vvphhSERhqk/Nv76Vkl8uvJwwHbQrR9KJx4L3PRkGCG24rix71jEuXVGZUsDNM3CUKnARx4MEab6
            GFHNkZ6DmoT/PFagngecHu+EwmuDtaG0rEkFrARwe+d8Ru0BN558abFb</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://pivotal.oktapreview.com/app/pivotal_pivotalcfstaging_1/k2lw4l5bPODCMIIDBRYZ/sso/saml"/><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://pivotal.oktapreview.com/app/pivotal_pivotalcfstaging_1/k2lw4l5bPODCMIIDBRYZ/sso/saml"/></md:IDPSSODescriptor></md:EntityDescriptor>
            """;

    private BootstrapSamlIdentityProviderData bootstrap;
    private SamlIdentityProviderDefinition singleAdd;
    private static final String SINGLE_ADD_ALIAS = "sample-alias";

    public static String sampleYaml = "  providers:\n" +
            "    okta-local:\n" +
            "      storeCustomAttributes: true\n" +
            "      idpMetadata: |\n" +
            "        " + TEST_XML_FILE_DATA.replace("\n", "\n        ") + "\n" +
            "      nameID: urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\n" +
            "      assertionConsumerIndex: 0\n" +
            "      metadataTrustCheck: true\n" +
            "      showSamlLoginLink: true\n" +
            "      linkText: 'Okta Preview 1'\n" +
            "      iconUrl: 'http://link.to/icon.jpg'\n" +
            "      " + AbstractIdentityProviderDefinition.EMAIL_DOMAIN_ATTR + ":\n" +
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
            "        " + TEST_XML_FILE_DATA.replace("\n", "\n        ") + "\n";

    @BeforeEach
    void beforeEach() {
        bootstrap = new BootstrapSamlIdentityProviderData(new SamlIdentityProviderConfigurator(mock(JdbcIdentityProviderProvisioning.class), new IdentityZoneManagerImpl(), mock(FixedHttpMetaDataProvider.class)));
        singleAdd = new SamlIdentityProviderDefinition()
                .setMetaDataLocation(BootstrapSamlIdentityProviderDataTests.XML_WITHOUT_ID.formatted(new RandomValueStringGenerator().generate()))
                .setIdpEntityAlias(SINGLE_ADD_ALIAS)
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
        for (Map.Entry<String, Object> entry : ((Map<String, Object>) tmpdata.get("providers")).entrySet()) {
            dataMap.put(entry.getKey(), (Map<String, Object>) entry.getValue());
        }
        return Collections.unmodifiableMap(dataMap);
    }

    private final Map<String, Map<String, Object>> sampleData = parseYaml(sampleYaml);

    @Test
    void cloneIdentityProviderDefinition() {
        SamlIdentityProviderDefinition clone = singleAdd.clone();
        assertThat(clone).isEqualTo(singleAdd).isNotSameAs(singleAdd);
    }

    @Test
    void addProviderDefinition() {
        bootstrap.setIdentityProviders(sampleData);
        bootstrap.afterPropertiesSet();
        testGetIdentityProviderDefinitions(4, false);
        assertThat(bootstrap.getSamlProviders()).allSatisfy(p -> assertThat(p.isOverride()).isTrue());
    }

    @Test
    void override() {
        sampleData.get("okta-local").put("override", false);
        bootstrap.setIdentityProviders(sampleData);
        bootstrap.afterPropertiesSet();
        testGetIdentityProviderDefinitions(4, false);
        assertThat(bootstrap
                .getSamlProviders()
                .stream()
                .filter(p -> "okta-local".equals(p.getProvider().getOriginKey()))
                .findFirst()
                .get()
                .isOverride()).isFalse();
    }

    @Test
    void getIdentityProviderDefinitions() {
        testGetIdentityProviderDefinitions(4);
    }

    private void testGetIdentityProviderDefinitions(int count) {
        testGetIdentityProviderDefinitions(count, true);
    }

    private void testGetIdentityProviderDefinitions(int count, boolean addData) {
        if (addData) {
            bootstrap.setIdentityProviders(sampleData);
            bootstrap.afterPropertiesSet();
        }
        List<SamlIdentityProviderDefinition> idps = bootstrap.getIdentityProviderDefinitions();
        assertThat(idps).hasSize(count);
        for (SamlIdentityProviderDefinition idp : idps) {
            switch (idp.getIdpEntityAlias()) {
                case "okta-local": {
                    assertThat(idp.getType()).isEqualTo(SamlIdentityProviderDefinition.MetadataLocation.DATA);
                    assertThat(idp.getMetaDataLocation().trim()).isEqualTo(TEST_XML_FILE_DATA.trim());
                    assertThat(idp.getNameID()).isEqualTo("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");
                    assertThat(idp.getAssertionConsumerIndex()).isZero();
                    assertThat(idp.getLinkText()).isEqualTo("Okta Preview 1");
                    assertThat(idp.getIconUrl()).isEqualTo("http://link.to/icon.jpg");
                    Map<String, Object> attributeMappings = new HashMap<>();
                    attributeMappings.put("given_name", "first_name");
                    attributeMappings.put("external_groups", Collections.singletonList("roles"));
                    assertThat(idp.getAttributeMappings()).isEqualTo(attributeMappings);
                    assertThat(idp.getExternalGroupsWhitelist()).isEqualTo(asList("admin", "user"));
                    assertThat(idp.isShowSamlLink()).isTrue();
                    assertThat(idp.isMetadataTrustCheck()).isTrue();
                    assertThat(idp.getEmailDomain()).contains("test.com", "test.org");
                    assertThat(idp.isStoreCustomAttributes()).isTrue();
                    assertThat(idp.getAuthnContext()).isNull();
                    break;
                }
                case "okta-local-2": {
                    assertThat(idp.getType()).isEqualTo(SamlIdentityProviderDefinition.MetadataLocation.DATA);
                    assertThat(idp.getNameID()).isEqualTo("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");
                    assertThat(idp.getAssertionConsumerIndex()).isZero();
                    assertThat(idp.getLinkText()).isEqualTo("Okta Preview 2");
                    assertThat(idp.getIconUrl()).isNull();
                    assertThat(idp.isShowSamlLink()).isTrue();
                    assertThat(idp.isMetadataTrustCheck()).isTrue();
                    assertThat(idp.isStoreCustomAttributes()).isTrue();
                    break;
                }
                case "okta-local-3": {
                    assertThat(idp.getType()).isEqualTo(SamlIdentityProviderDefinition.MetadataLocation.DATA);
                    assertThat(idp.getNameID()).isEqualTo("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");
                    assertThat(idp.getAssertionConsumerIndex()).isZero();
                    assertThat(idp.getLinkText()).isEqualTo("Use your corporate credentials");
                    assertThat(idp.getIconUrl()).isNull();
                    assertThat(idp.isShowSamlLink()).isTrue();
                    assertThat(idp.isMetadataTrustCheck()).isTrue();
                    break;
                }
                case SINGLE_ADD_ALIAS: {
                    assertThat(idp).isEqualTo(singleAdd).isNotSameAs(singleAdd);
                    break;
                }
                case "simplesamlphp-url": {
                    assertThat(idp.isShowSamlLink()).isTrue();
                    assertThat(idp.getLinkText()).isEqualTo("simplesamlphp-url");
                    assertThat(idp.isStoreCustomAttributes()).isFalse();
                    break;
                }
                case "custom-authncontext": {
                    assertThat(idp.getAuthnContext()).hasSize(2);
                    assertThat(idp.getAuthnContext().getFirst()).isEqualTo("custom-context");
                    assertThat(idp.getAuthnContext().get(1)).isEqualTo("another-context");
                    break;
                }

                default:
                    fail("Invalid IdpEntityAlias");
            }
        }
    }

    @Test
    void getIdentityProvidersWithLegacyValidProvider() {
        bootstrap.setLegacyIdpMetaData(TEST_XML_FILE_DATA_2);
        bootstrap.setLegacyIdpIdentityAlias("okta-local-3");
        bootstrap.setLegacyShowSamlLink(true);
        bootstrap.setLegacyNameId("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");
        testGetIdentityProviderDefinitions(5);
    }

    @Test
    void getIdentityProviders() {
        testGetIdentityProviderDefinitions(4);
    }

    @Test
    void canParseASimpleSamlConfig() {
        String yaml = """
                  providers:
                    my-okta:
                      assertionConsumerIndex: 0
                      emailDomain:\s
                      - mydomain.io
                      iconUrl: https://my.identityprovider.com/icon.png
                      idpMetadata: https://pivotal.oktapreview.com/app/abcdefghasdfsafjdsklf/sso/saml/metadata
                      linkText: Log in with Pivotal OktaPreview
                      metadataTrustCheck: true
                      nameID: urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress
                      showSamlLoginLink: false
                      signMetaData: false
                      signRequest: false
                      skipSslValidation: false
                      storeCustomAttributes: true\
                """;

        assertThatNoException().isThrownBy(() -> bootstrap.setIdentityProviders(parseYaml(yaml)));
        assertThatNoException().isThrownBy(() -> bootstrap.afterPropertiesSet());
    }

    @Test
    void setAddShadowUserOnLoginFromYaml() {
        String yaml = """
                  providers:
                    provider-without-shadow-user-definition:
                      storeCustomAttributes: true
                      idpMetadata: |
                        <?xml version="1.0" encoding="UTF-8"?>\
                        <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="provider1">\
                        <md:IDPSSODescriptor WantAuthnRequestsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">\
                        <md:KeyDescriptor use="signing">\
                        <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">\
                        <ds:X509Data><ds:X509Certificate>MIIDSTCCArKgAwIBAgIBADANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJhdzEOMAwGA1UECBMFYXJ1YmExDjAMBgNVBAoTBWFydWJhMQ4wDAYDVQQHEwVhcnViYTEOMAwGA1UECxMFYXJ1YmExDjAMBgNVBAMTBWFydWJhMR0wGwYJKoZIhvcNAQkBFg5hcnViYUBhcnViYS5hcjAeFw0xNTExMjAyMjI2MjdaFw0xNjExMTkyMjI2MjdaMHwxCzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5L39WqS9u0hnA+O7MCA/KlrAR4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vAfpOwznoD66DDCnQVpbCjtDYWX+x6imxn8HCYxhMol6ZnTbSsFW6VZjFMjQIDAQABo4HaMIHXMB0GA1UdDgQWBBTx0lDzjH/iOBnOSQaSEWQLx1syGDCBpwYDVR0jBIGfMIGcgBTx0lDzjH/iOBnOSQaSEWQLx1syGKGBgKR+MHwxCzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyggEAMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAYvBJ0HOZbbHClXmGUjGs+GS+xC1FO/am2suCSYqNB9dyMXfOWiJ1+TLJk+o/YZt8vuxCKdcZYgl4l/L6PxJ982SRhc83ZW2dkAZI4M0/Ud3oePe84k8jm3A7EvH5wi5hvCkKRpuRBwn3Ei+jCRouxTbzKPsuCVB+1sNyxMTXzf0=</ds:X509Certificate></ds:X509Data>\
                        </ds:KeyInfo>\
                        </md:KeyDescriptor>\
                        <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>\
                        <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://example.com"/>\
                        </md:IDPSSODescriptor>\
                        </md:EntityDescriptor>
                      nameID: urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress
                    provider-with-shadow-users-enabled:
                      storeCustomAttributes: false
                      idpMetadata: |
                        <?xml version="1.0" encoding="UTF-8"?>\
                        <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="provider2">\
                        <md:IDPSSODescriptor WantAuthnRequestsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">\
                        <md:KeyDescriptor use="signing">\
                        <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">\
                        <ds:X509Data><ds:X509Certificate>MIIDSTCCArKgAwIBAgIBADANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJhdzEOMAwGA1UECBMFYXJ1YmExDjAMBgNVBAoTBWFydWJhMQ4wDAYDVQQHEwVhcnViYTEOMAwGA1UECxMFYXJ1YmExDjAMBgNVBAMTBWFydWJhMR0wGwYJKoZIhvcNAQkBFg5hcnViYUBhcnViYS5hcjAeFw0xNTExMjAyMjI2MjdaFw0xNjExMTkyMjI2MjdaMHwxCzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5L39WqS9u0hnA+O7MCA/KlrAR4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vAfpOwznoD66DDCnQVpbCjtDYWX+x6imxn8HCYxhMol6ZnTbSsFW6VZjFMjQIDAQABo4HaMIHXMB0GA1UdDgQWBBTx0lDzjH/iOBnOSQaSEWQLx1syGDCBpwYDVR0jBIGfMIGcgBTx0lDzjH/iOBnOSQaSEWQLx1syGKGBgKR+MHwxCzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyggEAMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAYvBJ0HOZbbHClXmGUjGs+GS+xC1FO/am2suCSYqNB9dyMXfOWiJ1+TLJk+o/YZt8vuxCKdcZYgl4l/L6PxJ982SRhc83ZW2dkAZI4M0/Ud3oePe84k8jm3A7EvH5wi5hvCkKRpuRBwn3Ei+jCRouxTbzKPsuCVB+1sNyxMTXzf0=</ds:X509Certificate></ds:X509Data>\
                        </ds:KeyInfo>\
                        </md:KeyDescriptor>\
                        <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>\
                        <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://example.com"/>\
                        </md:IDPSSODescriptor>\
                        </md:EntityDescriptor>
                      nameID: urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress
                      addShadowUserOnLogin: true
                    provider-with-shadow-user-disabled:
                      idpMetadata: |
                        <?xml version="1.0" encoding="UTF-8"?>\
                        <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="provider3">\
                        <md:IDPSSODescriptor WantAuthnRequestsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">\
                        <md:KeyDescriptor use="signing">\
                        <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">\
                        <ds:X509Data><ds:X509Certificate>MIIDSTCCArKgAwIBAgIBADANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJhdzEOMAwGA1UECBMFYXJ1YmExDjAMBgNVBAoTBWFydWJhMQ4wDAYDVQQHEwVhcnViYTEOMAwGA1UECxMFYXJ1YmExDjAMBgNVBAMTBWFydWJhMR0wGwYJKoZIhvcNAQkBFg5hcnViYUBhcnViYS5hcjAeFw0xNTExMjAyMjI2MjdaFw0xNjExMTkyMjI2MjdaMHwxCzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5L39WqS9u0hnA+O7MCA/KlrAR4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vAfpOwznoD66DDCnQVpbCjtDYWX+x6imxn8HCYxhMol6ZnTbSsFW6VZjFMjQIDAQABo4HaMIHXMB0GA1UdDgQWBBTx0lDzjH/iOBnOSQaSEWQLx1syGDCBpwYDVR0jBIGfMIGcgBTx0lDzjH/iOBnOSQaSEWQLx1syGKGBgKR+MHwxCzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyggEAMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAYvBJ0HOZbbHClXmGUjGs+GS+xC1FO/am2suCSYqNB9dyMXfOWiJ1+TLJk+o/YZt8vuxCKdcZYgl4l/L6PxJ982SRhc83ZW2dkAZI4M0/Ud3oePe84k8jm3A7EvH5wi5hvCkKRpuRBwn3Ei+jCRouxTbzKPsuCVB+1sNyxMTXzf0=</ds:X509Certificate></ds:X509Data>\
                        </ds:KeyInfo>\
                        </md:KeyDescriptor>\
                        <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>\
                        <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://example.com"/>\
                        </md:IDPSSODescriptor>\
                        </md:EntityDescriptor>
                      nameID: urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress
                      addShadowUserOnLogin: false
                """;

        bootstrap.setIdentityProviders(parseYaml(yaml));
        bootstrap.afterPropertiesSet();

        for (SamlIdentityProviderDefinition def : bootstrap.getIdentityProviderDefinitions()) {
            switch (def.getIdpEntityAlias()) {
                case "provider-without-shadow-user-definition": {
                    assertThat(def.isAddShadowUserOnLogin()).as("If not specified, addShadowUserOnLogin is set to true").isTrue();
                    assertThat(def.isStoreCustomAttributes()).as("Override store custom attributes to true").isTrue();
                    break;
                }
                case "provider-with-shadow-users-enabled": {
                    assertThat(def.isAddShadowUserOnLogin()).as("addShadowUserOnLogin can be set to true").isTrue();
                    assertThat(def.isStoreCustomAttributes()).as("Default store custom attributes is false").isFalse();
                    break;
                }
                case "provider-with-shadow-user-disabled": {
                    assertThat(def.isAddShadowUserOnLogin()).as("addShadowUserOnLogin can be set to false").isFalse();
                    assertThat(def.isStoreCustomAttributes()).as("Default store custom attributes is false").isTrue();
                    break;
                }
                default:
                    fail("Unknown provider %s".formatted(def.getIdpEntityAlias()));
            }
        }
    }
}
