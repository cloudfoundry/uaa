/*
 * ****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 * ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.provider.saml;

import org.apache.commons.codec.binary.Base64;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.saml.idp.NonSnarlIdpMetadataManager;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.SamlConfig;
import org.hamcrest.Matchers;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.xml.signature.SignatureConstants;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate;
import org.springframework.security.saml.metadata.MetadataMemoryProvider;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import java.net.URLEncoder;

import static org.cloudfoundry.identity.uaa.provider.saml.idp.SamlTestUtils.SAML_IDP_METADATA_POST_ONLY;
import static org.cloudfoundry.identity.uaa.provider.saml.idp.SamlTestUtils.SAML_IDP_METADATA_REDIRECT_ONLY;
import static org.cloudfoundry.identity.uaa.zone.SamlConfig.SignatureAlgorithm.SHA256;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

public class SamlInitializationMockMvcTests extends InjectedMockContextTest {

    private NonSnarlMetadataManager spManager;
    private NonSnarlIdpMetadataManager idpManager;
    String entityID;
    private String entityAlias;
    private IdentityZoneProvisioning zoneProvisioning;
     private IdentityProviderProvisioning providerProvisioning;

    @Before
    public void setup() throws Exception {
        zoneProvisioning = getWebApplicationContext().getBean(IdentityZoneProvisioning.class);
        providerProvisioning = getWebApplicationContext().getBean(JdbcIdentityProviderProvisioning.class);
        spManager = getWebApplicationContext().getBean(NonSnarlMetadataManager.class);
        idpManager = getWebApplicationContext().getBean(NonSnarlIdpMetadataManager.class);
        entityID = getWebApplicationContext().getBean("samlEntityID", String.class);
        entityAlias = getWebApplicationContext().getBean("samlSPAlias", String.class);
    }

    @Before
    @After
    public void clear() {
        IdentityZoneHolder.clear();
    }

    @Test
    public void sp_initialized_in_non_snarl_metadata_manager() throws Exception {
        ExtendedMetadataDelegate localServiceProvider = spManager.getLocalServiceProvider();
        assertNotNull(localServiceProvider);
        MetadataProvider provider = localServiceProvider.getDelegate();
        assertNotNull(provider);
        assertTrue(provider instanceof MetadataMemoryProvider);
        String providerSpAlias = spManager.getProviderSpAlias(localServiceProvider);
        assertEquals(entityAlias, providerSpAlias);
        assertEquals(entityID, spManager.getEntityIdForAlias(providerSpAlias));
    }

    @Test
    public void sp_initialization_in_non_snarl_metadata_manager() throws Exception {
        String subdomain = new RandomValueStringGenerator().generate().toLowerCase();
        IdentityZone zone = new IdentityZone()
            .setConfig(new IdentityZoneConfiguration())
            .setSubdomain(subdomain)
            .setId(subdomain)
            .setName(subdomain);
        zone = zoneProvisioning.create(zone);
        IdentityZoneHolder.set(zone);
        ExtendedMetadataDelegate localServiceProvider = spManager.getLocalServiceProvider();
        assertNotNull(localServiceProvider);
        MetadataProvider provider = localServiceProvider.getDelegate();
        assertNotNull(provider);
        assertTrue(provider instanceof MetadataMemoryProvider);
        String providerSpAlias = spManager.getProviderSpAlias(localServiceProvider);
        assertEquals(subdomain + "." + entityAlias, providerSpAlias);
        assertEquals(addSubdomainToEntityId(entityID, subdomain), spManager.getEntityIdForAlias(providerSpAlias));
    }

    @Test
    public void test_saml_http_post_auth_request_signature_algorithm_for_http_post() throws Exception{
        SamlConfig.SignatureAlgorithm originalSignatureAlgorithm = IdentityZoneHolder.get().getConfig().getSamlConfig().getSignatureAlgorithm();
        IdentityZoneHolder.get().getConfig().getSamlConfig().setSignatureAlgorithm(SHA256);
        createUpdateSamlIDP(SAML_IDP_METADATA_POST_ONLY);

        MockHttpServletResponse response = getMockMvc().perform(MockMvcRequestBuilders.get("/saml/login/alias/cloudfoundry-saml-login?disco=true&idp=testzone1.cloudfoundry-saml-login")
        ).andReturn().getResponse();

        String samlRequest = parseSAMLRequestFromResponseHtml(response.getContentAsString());
        assertThat(samlRequest, Matchers.containsString(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256));

        IdentityZoneHolder.get().getConfig().getSamlConfig().setSignatureAlgorithm(originalSignatureAlgorithm);
    }

    @Test
    public void test_saml_http_redirect_auth_request_signature_algorithm_() throws Exception{
        SamlConfig.SignatureAlgorithm originalSignatureAlgorithm = IdentityZoneHolder.get().getConfig().getSamlConfig().getSignatureAlgorithm();
        IdentityZoneHolder.get().getConfig().getSamlConfig().setSignatureAlgorithm(SHA256);
        createUpdateSamlIDP(SAML_IDP_METADATA_REDIRECT_ONLY);

        MockHttpServletResponse response = getMockMvc().perform(MockMvcRequestBuilders.get("/saml/login/alias/cloudfoundry-saml-login?disco=true&idp=testzone1.cloudfoundry-saml-login")
        ).andReturn().getResponse();

        assertThat(response.getHeader(HttpHeaders.LOCATION), Matchers.containsString("SigAlg="
                + URLEncoder.encode(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256, "UTF-8")));

        IdentityZoneHolder.get().getConfig().getSamlConfig().setSignatureAlgorithm(originalSignatureAlgorithm);
    }

    private IdentityProvider<SamlIdentityProviderDefinition> createUpdateSamlIDP(String metadataLocation) {
        String zoneId = IdentityZoneHolder.get().getId();
        String alias = "testzone1.cloudfoundry-saml-login";
        try {
            IdentityProvider existingProvider = providerProvisioning.retrieveByOrigin(alias, zoneId);
            ((SamlIdentityProviderDefinition)existingProvider.getConfig()).setMetaDataLocation(metadataLocation);
            return providerProvisioning.update(existingProvider, zoneId);
        } catch(EmptyResultDataAccessException emtyResultDataAccessException) {
            SamlIdentityProviderDefinition def = new SamlIdentityProviderDefinition();
            def.setZoneId(zoneId);
            def.setMetaDataLocation(metadataLocation);
            def.setNameID("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");
            def.setAssertionConsumerIndex(0);
            def.setMetadataTrustCheck(false);
            def.setShowSamlLink(true);
            def.setIdpEntityAlias(alias);
            def.setLinkText("Login with Local SAML IdP(testzone1." + alias + ")");


            IdentityProvider<SamlIdentityProviderDefinition> idp = new IdentityProvider<>();
            idp.setIdentityZoneId(IdentityZoneHolder.get().getId());
            idp.setType(OriginKeys.SAML);
            idp.setActive(true);
            idp.setConfig(def);
            idp.setOriginKey(def.getIdpEntityAlias());
            idp.setName("Local SAML IdP for testzone1");
            idp = providerProvisioning.create(idp, zoneId);
            assertNotNull(idp.getId());
            return idp;
        }
    }

    private String parseSAMLRequestFromResponseHtml(String htmlContent) {
        //SamlRequest is base64 encoded into a hidden input in the html content
        String samlRequestHtmlPrefix = "SAMLRequest\" value=\"";
        String samlRequest = htmlContent.substring(htmlContent.indexOf(samlRequestHtmlPrefix));
        samlRequest = samlRequest.substring(samlRequestHtmlPrefix.length(), samlRequest.indexOf("\"/>"));
        samlRequest = new String(Base64.decodeBase64(samlRequest));
        return samlRequest;
    }
    public String addSubdomainToEntityId(String entityId, String subdomain) {
        if (UaaUrlUtils.isUrl(entityId)) {
            return UaaUrlUtils.addSubdomainToUrl(entityId, subdomain);
        } else {
            return subdomain + "." + entityId;
        }
    }

}
