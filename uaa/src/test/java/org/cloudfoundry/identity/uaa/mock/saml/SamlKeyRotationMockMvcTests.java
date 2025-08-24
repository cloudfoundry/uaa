/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */
package org.cloudfoundry.identity.uaa.mock.saml;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.provider.saml.TestCredentialObjects;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.SamlConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.context.WebApplicationContext;
import org.xmlunit.assertj.XmlAssert;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.provider.saml.Saml2TestUtils.xmlNamespaces;
import static org.cloudfoundry.identity.uaa.provider.saml.TestCredentialObjects.certificate1;
import static org.cloudfoundry.identity.uaa.provider.saml.TestCredentialObjects.certificate2;
import static org.cloudfoundry.identity.uaa.provider.saml.TestCredentialObjects.formatCert;
import static org.cloudfoundry.identity.uaa.provider.saml.TestCredentialObjects.keyName1;
import static org.cloudfoundry.identity.uaa.provider.saml.TestCredentialObjects.keyName2;
import static org.cloudfoundry.identity.uaa.provider.saml.TestCredentialObjects.legacyCertificate;
import static org.cloudfoundry.identity.uaa.provider.saml.TestCredentialObjects.legacyKey;
import static org.cloudfoundry.identity.uaa.provider.saml.TestCredentialObjects.legacyPassphrase;
import static org.cloudfoundry.identity.uaa.provider.saml.TestCredentialObjects.samlKey1;
import static org.cloudfoundry.identity.uaa.provider.saml.TestCredentialObjects.samlKey2;
import static org.springframework.http.MediaType.APPLICATION_XML;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@DefaultTestContext
class SamlKeyRotationMockMvcTests {
    private static final String METADATA_URL = "/saml/metadata";
    private static final String SIGNATURE_CERTIFICATE_XPATH_FORMAT = "//ds:Signature//ds:X509Certificate";
    public static final String KEY_DESCRIPTOR_CERTIFICATE_XPATH_FORMAT = "//md:SPSSODescriptor/md:KeyDescriptor[@use='%s']//ds:X509Certificate";

    private IdentityZone zone;

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    WebApplicationContext webApplicationContext;

    @BeforeEach
    void createZone() throws Exception {
        String id = new RandomValueStringGenerator().generate().toLowerCase();
        IdentityZone identityZone = new IdentityZone();
        identityZone.setId(id);
        identityZone.setSubdomain(id);
        identityZone.setName("Test Saml Key Zone");
        identityZone.setDescription("Testing SAML Key Rotation");
        Map<String, String> keys = Map.of("exampleKeyId", "s1gNiNg.K3y/t3XT");
        identityZone.getConfig().getTokenPolicy().setKeys(keys);
        SamlConfig samlConfig = new SamlConfig();
        samlConfig.setCertificate(legacyCertificate());
        samlConfig.setPrivateKey(legacyKey());
        samlConfig.setPrivateKeyPassword(legacyPassphrase());
        samlConfig.addKey(keyName1(), samlKey1());
        samlConfig.addKey(keyName2(), samlKey2());
        identityZone.getConfig().setSamlConfig(samlConfig);

        UaaClientDetails zoneAdminClient = new UaaClientDetails("admin", null,
                "openid",
                "client_credentials,authorization_code",
                "clients.admin,scim.read,scim.write",
                "http://test.redirect.com");
        zoneAdminClient.setClientSecret("admin-secret");
        MockMvcUtils.IdentityZoneCreationResult identityZoneCreationResult = MockMvcUtils
                .createOtherIdentityZoneAndReturnResult(mockMvc, webApplicationContext, zoneAdminClient, identityZone, false, id);
        zone = identityZoneCreationResult.getIdentityZone();
    }

    @Test
    void key_rotation() throws Exception {
        //default with three keys
        XmlAssert metadataAssert = getMetadataAssert();
        assertThatSigningKeyHasValues(metadataAssert, legacyCertificate(), certificate1(), certificate2());
        assertThatEncryptionKeyHasValues(metadataAssert, legacyCertificate());
        assertSignatureKeyHasValue(metadataAssert, legacyCertificate());

        //activate key1
        zone.getConfig().getSamlConfig().setActiveKeyId(keyName1());
        zone = MockMvcUtils.updateZone(mockMvc, zone);
        metadataAssert = getMetadataAssert();
        assertThatSigningKeyHasValues(metadataAssert, legacyCertificate(), certificate1(), certificate2());
        assertThatEncryptionKeyHasValues(metadataAssert, certificate1());
        assertSignatureKeyHasValue(metadataAssert, certificate1());

        //remove all but key2
        zone.getConfig().getSamlConfig().setKeys(new HashMap<>());
        zone.getConfig().getSamlConfig().addAndActivateKey(keyName2(), samlKey2());
        zone = MockMvcUtils.updateZone(mockMvc, zone);
        metadataAssert = getMetadataAssert();
        assertThatSigningKeyHasValues(metadataAssert, certificate2());
        assertThatEncryptionKeyHasValues(metadataAssert, certificate2());
        assertSignatureKeyHasValue(metadataAssert, certificate2());
    }

    @Test
    void check_metadata_signature_key() throws Exception {
        XmlAssert metadataAssert = getMetadataAssert();
        assertSignatureKeyHasValue(metadataAssert, legacyCertificate());

        zone.getConfig().getSamlConfig().setActiveKeyId(keyName1());
        zone = MockMvcUtils.updateZone(mockMvc, zone);

        metadataAssert = getMetadataAssert();
        assertSignatureKeyHasValue(metadataAssert, certificate1());
    }

    private XmlAssert getMetadataAssert() throws Exception {
        String metadata = mockMvc.perform(
                get(METADATA_URL)
                        .header("Host", zone.getSubdomain() + ".localhost")
                        .accept(APPLICATION_XML)
        )
        .andDo(print())
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        return XmlAssert.assertThat(metadata).withNamespaceContext(xmlNamespaces());
    }

    private void assertSignatureKeyHasValue(XmlAssert metadata, String expectedKey) {
        metadata.hasXPath(SIGNATURE_CERTIFICATE_XPATH_FORMAT)
                .isNotEmpty()
                .extractingText()
                .containsOnly(formatCert(expectedKey));
    }

    private void assertThatSigningKeyHasValues(XmlAssert xmlAssert, String... certificates) {
        assertThatXmlKeysOfTypeHasValues(xmlAssert, "signing", certificates);
    }

    private void assertThatEncryptionKeyHasValues(XmlAssert xmlAssert, String... certificates) {
        assertThatXmlKeysOfTypeHasValues(xmlAssert, "encryption", certificates);
    }

    private void assertThatXmlKeysOfTypeHasValues(XmlAssert xmlAssert, String type, String... certificates) {
        String[] cleanCerts = Arrays.stream(certificates).map(TestCredentialObjects::bare).toArray(String[]::new);
        xmlAssert.hasXPath(KEY_DESCRIPTOR_CERTIFICATE_XPATH_FORMAT.formatted(type))
                .isNotEmpty()
                .extractingText()
                .containsExactlyInAnyOrder(cleanCerts);
    }
}
