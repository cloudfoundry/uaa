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

package org.cloudfoundry.identity.uaa.mock.saml;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.saml.idp.JdbcSamlServiceProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.saml.idp.SamlServiceProvider;
import org.cloudfoundry.identity.uaa.provider.saml.idp.SamlServiceProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.saml.idp.SamlServiceProviderProvisioning;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimUserProvisioning;
import org.cloudfoundry.identity.uaa.test.ZoneSeederExtension;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.web.context.WebApplicationContext;
import org.xml.sax.InputSource;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import java.io.StringReader;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.getUaaSecurityContext;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.securityContext;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@DefaultTestContext
@ExtendWith(ZoneSeederExtension.class)
class SamlAuthenticationMockMvcTests {

    private RandomValueStringGenerator generator;

    private IdentityZone spZone;
    private IdentityZone idpZone;
    private String spZoneEntityId;
    private IdentityProvider<SamlIdentityProviderDefinition> idp;
    private SamlServiceProvider samlServiceProvider;

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private WebApplicationContext webApplicationContext;

    @SuppressWarnings("SpringJavaInjectionPointsAutowiringInspection")
    @BeforeEach
    void createSamlRelationship(
            @Autowired JdbcIdentityProviderProvisioning jdbcIdentityProviderProvisioning,
            @Autowired JdbcSamlServiceProviderProvisioning jdbcSamlServiceProviderProvisioning,
            @Autowired JdbcScimUserProvisioning jdbcScimUserProvisioning
    ) throws Exception {
        generator = new RandomValueStringGenerator();
        BaseClientDetails adminClient = new BaseClientDetails("admin", "", "", "client_credentials", "uaa.admin");
        adminClient.setClientSecret("adminsecret");
        spZone = createZone(adminClient);
        spZoneEntityId = spZone.getSubdomain() + ".cloudfoundry-saml-login";
        idpZone = createZone(adminClient);
        createIdp(jdbcIdentityProviderProvisioning);
        createSp(jdbcSamlServiceProviderProvisioning);
        createUser(jdbcScimUserProvisioning, idpZone);
    }

    @Test
    void sendAuthnRequestToIdp() throws Exception {
        String idpEntityId = idpZone.getSubdomain() + ".cloudfoundry-saml-login";
        MvcResult mvcResult = mockMvc.perform(
                get("/uaa/saml/discovery")
                        .contextPath("/uaa")
                        .header(HttpHeaders.HOST, spZone.getSubdomain() + ".localhost:8080")
                        .param("returnIDParam", "idp")
                        .param("entityID", spZoneEntityId)
                        .param("idp", idp.getOriginKey())
                        .param("isPassive", "true")
        )
                .andExpect(status().isFound())
                .andReturn();

        mvcResult = mockMvc.perform(
                get(mvcResult.getResponse().getRedirectedUrl())
                        .contextPath("/uaa")
                        .header(HttpHeaders.HOST, spZone.getSubdomain() + ".localhost:8080")
                        .session((MockHttpSession) mvcResult.getRequest().getSession())

        )
                .andDo(print())
                .andExpect(status().isOk())
                .andReturn();

        String body = mvcResult.getResponse().getContentAsString();
        String relayState = extractRelayState(body);
        String samlRequest = extractSamlRequest(body);
        mockMvc.perform(
                post("/uaa/saml/idp/SSO/alias/" + idpEntityId)
                        .contextPath("/uaa")
                        .header(HttpHeaders.HOST, idpZone.getSubdomain() + ".localhost:8080")
                        .param("RelayState", relayState)
                        .param("SAMLRequest", samlRequest)
        )
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("http://" + idpZone.getSubdomain() + ".localhost:8080/uaa/login"));
    }

    @Test
    void validateStaticAttributes(
            @Autowired JdbcSamlServiceProviderProvisioning jdbcSamlServiceProviderProvisioning
    ) throws Exception {
        samlServiceProvider.getConfig().getStaticCustomAttributes().put("portal_id", "portal");
        samlServiceProvider.getConfig().getStaticCustomAttributes().put("portal_emails", Arrays.asList("portal1@portal.test", "portal2@portal.test"));
        jdbcSamlServiceProviderProvisioning.update(samlServiceProvider, idpZone.getId());

        String samlResponse = performIdpAuthentication();
        String xml = extractAssertion(samlResponse, true);
        XPath xpath = XPathFactory.newInstance().newXPath();
        String emails = (String) xpath.evaluate("//*[local-name()='Attribute'][@*[local-name()='Name' and .='portal_emails']]", new InputSource(new StringReader(xml)), XPathConstants.STRING);
        assertThat(emails, containsString("portal1@portal.test"));
        assertThat(emails, containsString("portal2@portal.test"));
    }

    @Test
    void validateCustomEmailAttribute(
            @Autowired JdbcSamlServiceProviderProvisioning jdbcSamlServiceProviderProvisioning
    ) throws Exception {
        samlServiceProvider.getConfig().getAttributeMappings().put("email", "primary-email");
        jdbcSamlServiceProviderProvisioning.update(samlServiceProvider, idpZone.getId());

        String samlResponse = performIdpAuthentication();
        String xml = extractAssertion(samlResponse, true);
        XPath xpath = XPathFactory.newInstance().newXPath();
        String emails = (String) xpath.evaluate("//*[local-name()='Attribute'][@*[local-name()='Name' and .='primary-email']]", new InputSource(new StringReader(xml)), XPathConstants.STRING);
        assertThat(emails, equalTo("test@test.org"));
    }

    @Test
    void spIsAuthenticated() throws Exception {
        String samlResponse = performIdpAuthentication();
        String xml = extractAssertion(samlResponse, false);
        String subdomain = spZone.getSubdomain();
        mockMvc.perform(
                post("/uaa/saml/SSO/alias/" + spZoneEntityId)
                        .contextPath("/uaa")
                        .header(HttpHeaders.HOST, subdomain + ".localhost:8080")
                        .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                        .param("SAMLResponse", xml)
        )
                .andExpect(authenticated());
    }

    private String performIdpAuthentication() throws Exception {
        RequestPostProcessor marissa = securityContext(getUaaSecurityContext("marissa", webApplicationContext, idpZone));
        return mockMvc.perform(
                get("/saml/idp/initiate")
                        .header("Host", idpZone.getSubdomain() + ".localhost")
                        .param("sp", spZoneEntityId)
                        .with(marissa)
        )
                .andDo(print())
                .andReturn().getResponse().getContentAsString();
    }

    private String getSamlMetadata(String subdomain, String url) throws Exception {
        return mockMvc.perform(
                get(url)
                        .header("Host", subdomain + ".localhost")
        )
                .andReturn().getResponse().getContentAsString();
    }

    private static void createUser(
            JdbcScimUserProvisioning jdbcScimUserProvisioning,
            IdentityZone identityZone
    ) {
        ScimUser user = new ScimUser(null, "marissa", "first", "last");
        user.setPrimaryEmail("test@test.org");
        jdbcScimUserProvisioning.createUser(user, "secret", identityZone.getId());
    }

    private void createSp(SamlServiceProviderProvisioning spProvisioning) throws Exception {
        SamlServiceProviderDefinition spDefinition = new SamlServiceProviderDefinition();
        spDefinition.setEnableIdpInitiatedSso(true);
        spDefinition.setMetaDataLocation(getSamlMetadata(spZone.getSubdomain(), "/saml/metadata"));
        Map<String, Object> staticAttributes = new HashMap<>();
        spDefinition.setStaticCustomAttributes(staticAttributes);
        samlServiceProvider = new SamlServiceProvider()
                .setIdentityZoneId(idpZone.getId())
                .setEntityId(spZoneEntityId)
                .setConfig(spDefinition)
                .setActive(true)
                .setName("SAML SP for Mock Tests");
        samlServiceProvider = spProvisioning.create(samlServiceProvider, idpZone.getId());
    }

    private void createIdp(IdentityProviderProvisioning idpProvisioning) throws Exception {
        idp = new IdentityProvider<>()
                .setType(OriginKeys.SAML)
                .setOriginKey(idpZone.getSubdomain())
                .setActive(true)
                .setName("SAML IDP for Mock Tests")
                .setIdentityZoneId(spZone.getId());
        SamlIdentityProviderDefinition idpDefinition = new SamlIdentityProviderDefinition()
                .setMetaDataLocation(getSamlMetadata(idpZone.getSubdomain(), "/saml/idp/metadata"))
                .setIdpEntityAlias(idp.getOriginKey())
                .setLinkText(idp.getName())
                .setZoneId(spZone.getId());

        idp.setConfig(idpDefinition);
        idp = idpProvisioning.create(idp, spZone.getId());
    }

    private IdentityZone createZone(BaseClientDetails adminClient) throws Exception {
        return MockMvcUtils.createOtherIdentityZoneAndReturnResult(
                generator.generate(),
                mockMvc,
                webApplicationContext,
                adminClient
        ).getIdentityZone();
    }

    private static String extractAssertion(String response, boolean decode) {
        String searchFor = "name=\"SAMLResponse\" value=\"";
        return extractFormParameter(searchFor, response, decode);
    }

    private static String extractSamlRequest(String response) {
        String searchFor = "name=\"SAMLRequest\" value=\"";
        return extractFormParameter(searchFor, response, false);
    }

    private static String extractRelayState(String response) {
        String searchFor = "name=\"RelayState\" value=\"";
        return extractFormParameter(searchFor, response, false);
    }

    private static String extractFormParameter(String searchFor, String response, boolean decode) {
        int start = response.indexOf(searchFor) + searchFor.length();
        assertThat("Must find the SAML response in output\n" + response, start, greaterThan(searchFor.length()));
        int end = response.indexOf("\"/>", start);
        assertThat("Must find the SAML response in output\n" + response, end, greaterThan(start));
        String encoded = response.substring(start, end);
        if (decode) {
            return new String(Base64.getDecoder().decode(encoded));
        } else {
            return encoded;
        }
    }
}
