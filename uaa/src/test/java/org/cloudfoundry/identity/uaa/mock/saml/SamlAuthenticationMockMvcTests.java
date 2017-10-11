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
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
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
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.greaterThan;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.securityContext;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

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
                .header("Host", subdomain+".localhost")
        )
            .andReturn().getResponse().getContentAsString();
    }

    @Before
    public void createSamlRelationship() throws Exception {
        BaseClientDetails adminClient = new BaseClientDetails("admin","","","client_credentials","uaa.admin");
        adminClient.setClientSecret("adminsecret");
        spZone = createZone(adminClient);
        idpZone = createZone(adminClient);
        idpProvisioning = getWebApplicationContext().getBean(JdbcIdentityProviderProvisioning.class);
        spProvisioning = getWebApplicationContext().getBean(JdbcSamlServiceProviderProvisioning.class);
        createIdp(idpProvisioning);
        createSp(spProvisioning);
        createUser();
    }

    @Test
    public void validate_static_attributes() throws Exception {
        sp.getConfig().getStaticCustomAttributes().put("portal_id","portal");
        sp.getConfig().getStaticCustomAttributes().put("portal_emails", Arrays.asList("portal1@portal.test", "portal2@portal.test"));
        spProvisioning.update(sp, idpZone.getIdentityZone().getId());

        RequestPostProcessor marissa = securityContext(getUaaSecurityContext("marissa", getWebApplicationContext(), idpZone.getIdentityZone()));
        String assertion = getMockMvc().perform(
            get("/saml/idp/initiate")
                .header("Host", idpZone.getIdentityZone().getSubdomain()+".localhost")
                .param("sp", entityId)
                .with(marissa)
        )
            .andReturn().getResponse().getContentAsString();

        String xml = extractAssertion(assertion);
        XPath xpath = XPathFactory.newInstance().newXPath();
        String emails = (String) xpath.evaluate("//*[local-name()='Attribute'][@*[local-name()='Name' and .='portal_emails']]", new InputSource(new StringReader(xml)), XPathConstants.STRING);
        assertThat(emails, containsString("portal1@portal.test"));
        assertThat(emails, containsString("portal2@portal.test"));

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
        spDefinition.setMetaDataLocation(getSamlMetadata(spZone.getIdentityZone().getSubdomain(), "/saml/metadata"));
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
            .setMetaDataLocation(getSamlMetadata(idpZone.getIdentityZone().getSubdomain(), "/saml/idp/metadata"))
            .setIdpEntityAlias(idp.getOriginKey())
            .setLinkText(idp.getName())
            .setZoneId(spZone.getIdentityZone().getId());

        idp.setConfig(idpDefinition);
        idp = idpProvisioning.create(idp, spZone.getIdentityZone().getId());
    }

    public IdentityZoneCreationResult createZone(BaseClientDetails adminClient) throws Exception {
        return MockMvcUtils.createOtherIdentityZoneAndReturnResult(
            generator.generate(),
            getMockMvc(),
            getWebApplicationContext(),
            adminClient
        );
    }



    public String extractAssertion(String response) {
        String searchFor = "name=\"SAMLResponse\" value=\"";
        int start = response.indexOf(searchFor) + searchFor.length();
        assertThat("Must find the SAML response in output\n"+response, start, greaterThan(searchFor.length()));
        int end = response.indexOf("\"/>", start);
        assertThat("Must find the SAML response in output\n"+response, end, greaterThan(start));
        return new String(Base64.getDecoder().decode(response.substring(start, end)));
    }

}
