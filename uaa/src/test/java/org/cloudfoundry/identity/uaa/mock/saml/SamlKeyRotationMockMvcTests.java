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
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.provider.saml.idp.SamlTestUtils;
import org.cloudfoundry.identity.uaa.saml.SamlKey;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.SamlConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.context.WebApplicationContext;
import org.w3c.dom.NodeList;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.provider.saml.SamlKeyManagerFactoryTests.*;
import static org.cloudfoundry.identity.uaa.provider.saml.idp.SamlTestUtils.getCertificates;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.junit.Assert.*;
import static org.springframework.http.MediaType.APPLICATION_XML;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@DefaultTestContext
class SamlKeyRotationMockMvcTests {

    private IdentityZone zone;
    private SamlKey samlKey2;

    private MockMvc mockMvc;

    @BeforeEach
    void createZone(
            @Autowired WebApplicationContext webApplicationContext,
            @Autowired MockMvc mockMvc
    ) throws Exception {
        this.mockMvc = mockMvc;

        String id = new RandomValueStringGenerator().generate().toLowerCase();
        IdentityZone identityZone = new IdentityZone();
        identityZone.setId(id);
        identityZone.setSubdomain(id);
        identityZone.setName("Test Saml Key Zone");
        identityZone.setDescription("Testing SAML Key Rotation");
        Map<String, String> keys = new HashMap<>();
        keys.put("exampleKeyId", "s1gNiNg.K3y/t3XT");
        identityZone.getConfig().getTokenPolicy().setKeys(keys);
        SamlConfig samlConfig = new SamlConfig();
        samlConfig.setCertificate(legacyCertificate);
        samlConfig.setPrivateKey(legacyKey);
        samlConfig.setPrivateKeyPassword(legacyPassphrase);
        SamlKey samlKey1 = new SamlKey(key1, passphrase1, certificate1);
        samlConfig.addKey("key1", samlKey1);
        samlKey2 = new SamlKey(key2, passphrase2, certificate2);
        samlConfig.addKey("key2", samlKey2);
        identityZone.getConfig().setSamlConfig(samlConfig);

        BaseClientDetails zoneAdminClient = new BaseClientDetails("admin", null,
            "openid",
            "client_credentials,authorization_code",
            "clients.admin,scim.read,scim.write",
            "http://test.redirect.com");
        zoneAdminClient.setClientSecret("admin-secret");
        MockMvcUtils.IdentityZoneCreationResult identityZoneCreationResult = MockMvcUtils
            .createOtherIdentityZoneAndReturnResult(mockMvc, webApplicationContext, zoneAdminClient, identityZone, false, id);
        zone = identityZoneCreationResult.getIdentityZone();
    }

    @ParameterizedTest
    @ValueSource(strings = {"/saml/idp/metadata", "/saml/metadata"})
    void key_rotation(String url) throws Exception {
        //default with three keys
        String metadata = getMetadata(url);
        List<String> signatureVerificationKeys = getCertificates(metadata, "signing");
        assertThat(signatureVerificationKeys, containsInAnyOrder(clean(legacyCertificate), clean(certificate1), clean(certificate2)));
        List<String> encryptionKeys = getCertificates(metadata, "encryption");
        assertThat(encryptionKeys, containsInAnyOrder(clean(legacyCertificate)));
        evaluateSignatureKey(metadata, legacyCertificate);

        //activate key1
        zone.getConfig().getSamlConfig().setActiveKeyId("key1");
        zone = MockMvcUtils.updateZone(mockMvc, zone);
        metadata = getMetadata(url);
        signatureVerificationKeys = getCertificates(metadata, "signing");
        assertThat(signatureVerificationKeys, containsInAnyOrder(clean(legacyCertificate), clean(certificate1), clean(certificate2)));
        encryptionKeys = getCertificates(metadata, "encryption");
        evaluateSignatureKey(metadata, certificate1);
        assertThat(encryptionKeys, containsInAnyOrder(clean(certificate1)));

        //remove all but key2
        zone.getConfig().getSamlConfig().setKeys(new HashMap<>());
        zone.getConfig().getSamlConfig().addAndActivateKey("key2", samlKey2);
        zone = MockMvcUtils.updateZone(mockMvc, zone);
        metadata = getMetadata(url);
        signatureVerificationKeys = getCertificates(metadata, "signing");
        assertThat(signatureVerificationKeys, containsInAnyOrder(clean(certificate2)));
        evaluateSignatureKey(metadata, certificate2);
        encryptionKeys = getCertificates(metadata, "encryption");
        assertThat(encryptionKeys, containsInAnyOrder(clean(certificate2)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"/saml/idp/metadata", "/saml/metadata"})
    void check_metadata_signature_key(String url) throws Exception {
        String metadata = getMetadata(url);

        evaluateSignatureKey(metadata, legacyCertificate);

        zone.getConfig().getSamlConfig().setActiveKeyId("key1");
        zone = MockMvcUtils.updateZone(mockMvc, zone);

        metadata = getMetadata(url);

        evaluateSignatureKey(metadata, certificate1);
    }

    private String getMetadata(String uri) throws Exception {
        return mockMvc.perform(
                get(uri)
                        .header("Host", zone.getSubdomain() + ".localhost")
                        .accept(APPLICATION_XML)
        )
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
    }

    private String clean(String cert) {
        return cert.replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replace("\n", "");
    }

    private void evaluateSignatureKey(String metadata, String expectedKey) throws Exception {
        String xpath = "//*[local-name() = 'Signature']//*[local-name() = 'X509Certificate']/text()";
        NodeList nodeList = SamlTestUtils.evaluateXPathExpression(SamlTestUtils.getMetadataDoc(metadata), xpath);
        assertNotNull(nodeList);
        assertEquals(1, nodeList.getLength());
        assertEquals(clean(expectedKey), clean(nodeList.item(0).getNodeValue()));
    }

}
