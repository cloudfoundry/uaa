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

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import java.io.StringReader;
import java.net.URI;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.IdentityZoneCreationResult;
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

import org.junit.Before;
import org.junit.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.xml.sax.InputSource;

import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.getUaaSecurityContext;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.securityContext;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class SamlAuthenticationMockMvcTests extends InjectedMockContextTest {

    private RandomValueStringGenerator generator = new RandomValueStringGenerator() {
        @Override
        public String generate() {
            return super.generate().toLowerCase();
        }
    };

    IdentityZoneCreationResult spZone, idpZone;
    private String entityId;
    private IdentityProvider<SamlIdentityProviderDefinition> idp;
    private SamlServiceProvider sp;
    private IdentityProviderProvisioning idpProvisioning;
    private SamlServiceProviderProvisioning spProvisioning;

    public String getSamlMetadata(String subdomain, String url) throws Exception {
        return getMockMvc().perform(
            get(url)
                .contextPath("/uaa")
                .header("Host", subdomain+".localhost")
        )
            .andReturn().getResponse().getContentAsString();
    }

    @Before
    public void createSamlRelationship() throws Exception {
        BaseClientDetails adminClient = new BaseClientDetails("admin","","","client_credentials","uaa.admin");
        adminClient.setClientSecret("adminsecret");
        spZone = createZone("sp",adminClient);
        idpZone = createZone("idp",adminClient);
        idpProvisioning = getWebApplicationContext().getBean(JdbcIdentityProviderProvisioning.class);
        spProvisioning = getWebApplicationContext().getBean(JdbcSamlServiceProviderProvisioning.class);
        createIdp(idpProvisioning);
        createSp(spProvisioning);
        createUser();
    }

    @Test
    public void send_authn_request_to_idp() throws Exception {
        String spEntityId = spZone.getIdentityZone().getSubdomain() + ".cloudfoundry-saml-login";
        String idpEntityId = idpZone.getIdentityZone().getSubdomain() + ".cloudfoundry-saml-login";
        MvcResult mvcResult = getMockMvc().perform(
            get("/uaa/saml/discovery")
                .contextPath("/uaa")
                .header(HttpHeaders.HOST, spZone.getIdentityZone().getSubdomain() + ".localhost")
                .param("returnIDParam", "idp")
                .param("entityID", spEntityId)
                .param("idp", idp.getOriginKey())
                .param("isPassive", "true")
        )
            .andDo(print())
            .andExpect(status().isFound())
            .andReturn();

        URI spAuthRequestUri = new URI(mvcResult.getResponse().getRedirectedUrl());

        //end point should be protected
        getMockMvc().perform(
            get(spAuthRequestUri)
                .contextPath("/uaa")
                .header(HttpHeaders.HOST, idpZone.getIdentityZone().getSubdomain() + ".localhost")
        )
            .andDo(print())
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("http://"+idpZone.getIdentityZone().getSubdomain() + ".localhost/uaa/login"));

        SecurityContext uaaSecurityContext = MockMvcUtils.getUaaSecurityContext("marissa", getWebApplicationContext(), idpZone.getIdentityZone());
        mvcResult = getMockMvc().perform(
            get(spAuthRequestUri)
                .contextPath("/uaa")
                .header(HttpHeaders.HOST, idpZone.getIdentityZone().getSubdomain() + ".localhost")
                .with(authentication(uaaSecurityContext.getAuthentication()))
        )
            .andDo(print())
            .andExpect(status().isOk())
            .andReturn();

        String body = mvcResult.getResponse().getContentAsString();
        assertNotNull(extractRelayState(body));
        String xml = extractAssertion(body, false);
        performSPAuthentication(xml)
            .andExpect(authenticated());

    }

    @Test
    public void validate_static_attributes() throws Exception {
        sp.getConfig().getStaticCustomAttributes().put("portal_id","portal");
        sp.getConfig().getStaticCustomAttributes().put("portal_emails", Arrays.asList("portal1@portal.test", "portal2@portal.test"));
        spProvisioning.update(sp, idpZone.getIdentityZone().getId());

        String samlResponse = performIdpAuthentication();
        String xml = extractAssertion(samlResponse, true);
        XPath xpath = XPathFactory.newInstance().newXPath();
        String emails = (String) xpath.evaluate("//*[local-name()='Attribute'][@*[local-name()='Name' and .='portal_emails']]", new InputSource(new StringReader(xml)), XPathConstants.STRING);
        assertThat(emails, containsString("portal1@portal.test"));
        assertThat(emails, containsString("portal2@portal.test"));
    }

    @Test
    public void validate_custom_email_attribute() throws Exception {
        sp.getConfig().getAttributeMappings().put("email","primary-email");
        spProvisioning.update(sp, idpZone.getIdentityZone().getId());

        String samlResponse = performIdpAuthentication();
        String xml = extractAssertion(samlResponse, true);
        XPath xpath = XPathFactory.newInstance().newXPath();
        String emails = (String) xpath.evaluate("//*[local-name()='Attribute'][@*[local-name()='Name' and .='primary-email']]", new InputSource(new StringReader(xml)), XPathConstants.STRING);
        assertThat(emails, equalTo("test@test.org"));
    }

    @Test
    public void sp_is_authenticated() throws Exception {
        String samlResponse = performIdpAuthentication();
        String xml = extractAssertion(samlResponse, false);
        performSPAuthentication(xml)
            .andExpect(authenticated());
    }

    public ResultActions performSPAuthentication(String assertion) throws Exception {
        String spEntityId = spZone.getIdentityZone().getSubdomain() + ".cloudfoundry-saml-login";
        return getMockMvc().perform(
            post("/uaa/saml/SSO/alias/"+spEntityId)
                .contextPath("/uaa")
                .header(HttpHeaders.HOST, spZone.getIdentityZone().getSubdomain()+".localhost")
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .param("SAMLResponse", assertion)
        );
    }

    public String performIdpAuthentication() throws Exception {
        RequestPostProcessor marissa = securityContext(getUaaSecurityContext("marissa", getWebApplicationContext(), idpZone.getIdentityZone()));
        return getMockMvc().perform(
            get("/saml/idp/initiate")
                .header("Host", idpZone.getIdentityZone().getSubdomain()+".localhost")
                .param("sp", entityId)
                .with(marissa)
        )
            .andDo(print())
            .andReturn().getResponse().getContentAsString();
    }

    public void createUser() throws Exception {
        JdbcScimUserProvisioning userProvisioning = getWebApplicationContext().getBean(JdbcScimUserProvisioning.class);
        ScimUser user = new ScimUser(null, "marissa", "first", "last");
        user.setPrimaryEmail("test@test.org");
        userProvisioning.createUser(user, "secret", idpZone.getIdentityZone().getId());
    }

    public void createSp(SamlServiceProviderProvisioning spProvisioning) throws Exception {
        SamlServiceProviderDefinition spDefinition = new SamlServiceProviderDefinition();
        spDefinition.setEnableIdpInitiatedSso(true);
        spDefinition.setMetaDataLocation(getSamlMetadata(spZone.getIdentityZone().getSubdomain(), "/uaa/saml/metadata"));
        Map<String, Object> staticAttributes = new HashMap<>();
        spDefinition.setStaticCustomAttributes(staticAttributes);
        entityId = spZone.getIdentityZone().getSubdomain() + ".cloudfoundry-saml-login";
        sp = new SamlServiceProvider()
            .setIdentityZoneId(idpZone.getIdentityZone().getId())
            .setEntityId(entityId)
            .setConfig(spDefinition)
            .setActive(true)
            .setName("SAML SP for Mock Tests");
        sp = spProvisioning.create(sp, idpZone.getIdentityZone().getId());
    }

    public void createIdp(IdentityProviderProvisioning idpProvisioning) throws Exception {
        idp = new IdentityProvider<>()
            .setType(OriginKeys.SAML)
            .setOriginKey(idpZone.getIdentityZone().getSubdomain())
            .setActive(true)
            .setName("SAML IDP for Mock Tests")
            .setIdentityZoneId(spZone.getIdentityZone().getId());
        SamlIdentityProviderDefinition idpDefinition = new SamlIdentityProviderDefinition()
            .setMetaDataLocation(getSamlMetadata(idpZone.getIdentityZone().getSubdomain(), "/uaa/saml/idp/metadata"))
            .setIdpEntityAlias(idp.getOriginKey())
            .setLinkText(idp.getName())
            .setZoneId(spZone.getIdentityZone().getId());

        idp.setConfig(idpDefinition);
        idp = idpProvisioning.create(idp, spZone.getIdentityZone().getId());
    }

    public IdentityZoneCreationResult createZone(String prefix, BaseClientDetails adminClient) throws Exception {

        IdentityZoneCreationResult result = MockMvcUtils.createOtherIdentityZoneAndReturnResult(
            prefix + "-" + generator.generate(),
            getMockMvc(),
            getWebApplicationContext(),
            adminClient
        );
        return result;
    }



    public String extractAssertion(String response, boolean decode) {
        String searchFor = "name=\"SAMLResponse\" value=\"";
        return extractFormParameter(searchFor, response, decode);
    }

    public String extractSamlRequest(String response) {
        String searchFor = "name=\"SAMLRequest\" value=\"";
        return extractFormParameter(searchFor, response, false);
    }

    public String extractRelayState(String response) {
        String searchFor = "name=\"RelayState\" value=\"";
        return extractFormParameter(searchFor, response, false);
    }


    public String extractFormParameter(String searchFor, String response, boolean decode) {
        int start = response.indexOf(searchFor) + searchFor.length();
        assertThat("Must find the SAML response in output\n"+response, start, greaterThan(searchFor.length()));
        int end = response.indexOf("\"/>", start);
        assertThat("Must find the SAML response in output\n"+response, end, greaterThan(start));
        String encoded = response.substring(start, end);
        if (decode) {
            return new String(Base64.getDecoder().decode(encoded));
        } else {
            return encoded;
        }
    }



}
