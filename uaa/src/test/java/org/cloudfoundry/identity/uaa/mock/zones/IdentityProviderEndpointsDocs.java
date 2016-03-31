/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.mock.zones;

import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.RawXOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.saml.BootstrapSamlIdentityProviderConfiguratorTests;
import org.cloudfoundry.identity.uaa.test.TestApplicationEventListener;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.cloudfoundry.identity.uaa.zone.event.IdentityProviderModifiedEvent;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.restdocs.payload.FieldDescriptor;
import org.springframework.test.web.servlet.ResultActions;

import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.restdocs.headers.HeaderDocumentation.headerWithName;
import static org.springframework.restdocs.headers.HeaderDocumentation.requestHeaders;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.post;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.preprocessRequest;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.preprocessResponse;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.prettyPrint;
import static org.springframework.restdocs.payload.JsonFieldType.ARRAY;
import static org.springframework.restdocs.payload.JsonFieldType.BOOLEAN;
import static org.springframework.restdocs.payload.JsonFieldType.NUMBER;
import static org.springframework.restdocs.payload.JsonFieldType.OBJECT;
import static org.springframework.restdocs.payload.JsonFieldType.STRING;
import static org.springframework.restdocs.payload.PayloadDocumentation.fieldWithPath;
import static org.springframework.restdocs.payload.PayloadDocumentation.requestFields;
import static org.springframework.restdocs.payload.PayloadDocumentation.responseFields;
import static org.springframework.restdocs.snippet.Attributes.key;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class IdentityProviderEndpointsDocs extends InjectedMockContextTest {
    private TestClient testClient = null;
    private String adminToken;
    private String identityToken;
    private MockMvcUtils mockMvcUtils;
    private TestApplicationEventListener<IdentityProviderModifiedEvent> eventListener;
    private IdentityProviderProvisioning identityProviderProvisioning;
    private String lowPrivilegeToken;

    @Before
    public void setUp() throws Exception {
        testClient = new TestClient(getMockMvc());

        mockMvcUtils = MockMvcUtils.utils();

        adminToken = testClient.getClientCredentialsOAuthAccessToken(
            "admin",
            "adminsecret",
            "");

        identityToken = testClient.getClientCredentialsOAuthAccessToken(
            "identity",
            "identitysecret",
            "zones.write");

        lowPrivilegeToken = testClient.getClientCredentialsOAuthAccessToken(
            "admin",
            "adminsecret",
            "scim.read");

        identityProviderProvisioning = getWebApplicationContext().getBean(IdentityProviderProvisioning.class);
    }

    @After
    public void clearUaaConfig() throws Exception {
        getWebApplicationContext().getBean(JdbcTemplate.class).update("UPDATE identity_provider SET config=null WHERE origin_key='uaa'");
    }


    @Test
    public void createIdentityProvider() throws Exception {
        IdentityProvider identityProvider = new IdentityProvider();
        identityProvider.setType(OriginKeys.UAA);
        identityProvider.setName("UAA Provider");
        identityProvider.setOriginKey("UAA");
        identityProvider.setConfig(new UaaIdentityProviderDefinition(null, null));

        FieldDescriptor[] fieldDescriptors = {
            fieldWithPath("name").attributes(key("constraints").value("Required")).description(""),
            fieldWithPath("originKey").attributes(key("constraints").value("Required")).description(""),

            fieldWithPath("type").attributes(key("constraints").value("Optional")).description(""),
            fieldWithPath("id").attributes(key("constraints").value("Optional")).description(""),
            fieldWithPath("active").attributes(key("constraints").value("Optional")).description("Defaults to true."),
            fieldWithPath("version").attributes(key("constraints").value("Optional")).description(""),
            fieldWithPath("identityZoneId").attributes(key("constraints").value("Optional")).description(""),
            fieldWithPath("config").attributes(key("constraints").value("Optional")).description(""),

            fieldWithPath("config.minLength").type(NUMBER).attributes(key("constraints").value("Required")).description("").optional(),
            fieldWithPath("config.maxLength").type(NUMBER).attributes(key("constraints").value("Required")).description("").optional(),
            fieldWithPath("config.requireUpperCaseCharacter").type(NUMBER).attributes(key("constraints").value("Required")).description("").optional(),
            fieldWithPath("config.requireLowerCaseCharacter").type(NUMBER).attributes(key("constraints").value("Required")).description("").optional(),
            fieldWithPath("config.requireDigit").type(NUMBER).attributes(key("constraints").value("Required")).description("").optional(),
            fieldWithPath("config.requireSpecialCharacter").type(NUMBER).attributes(key("constraints").value("Required")).description("").optional(),
            fieldWithPath("config.expirePasswordInMonths").type(NUMBER).attributes(key("constraints").value("Required")).description("").optional(),
            fieldWithPath("config.lockoutPeriodSeconds").type(NUMBER).attributes(key("constraints").value("Required")).description("").optional(),
            fieldWithPath("config.lockoutAfterFailures").type(NUMBER).attributes(key("constraints").value("Required")).description("").optional(),
            fieldWithPath("config.countFailuresWithin").type(NUMBER).attributes(key("constraints").value("Required")).description("").optional(),
            fieldWithPath("config.disableInternalUserManagement").type(BOOLEAN).attributes(key("constraints").value("Optional")).description("").optional(),
            fieldWithPath("config.emailDomain").type(ARRAY).attributes(key("constraints").value("Optional")).description("").optional(),
            fieldWithPath("config.providerDescription").type(STRING).attributes(key("constraints").value("Optional")).description("").optional(),

            fieldWithPath("created").ignored(),
            fieldWithPath("last_modified").ignored()
        };

        ResultActions resultActions = getMockMvc().perform(post("/identity-providers")
            .header("Authorization", "Bearer " + adminToken)
            .contentType(APPLICATION_JSON)
            .content(JsonUtils.writeValueAsString(identityProvider)))
            .andExpect(status().isCreated());

        resultActions.andDo(document("{ClassName}/{methodName}",
            preprocessRequest(prettyPrint()),
            preprocessResponse(prettyPrint()),
            requestHeaders(
                headerWithName("Authorization").description("Bearer token containing `zones.read` or `zones.<zone id>.admin` or `zones.<zone id>.read`")
            ),
            requestFields(fieldDescriptors),
            responseFields(fieldDescriptors)
        ));
    }

    @Test
    public void createSAMLIdentityProvider() throws Exception {
        IdentityProvider identityProvider = MultitenancyFixture.identityProvider("SAML", IdentityZone.getUaa().getId());
        identityProvider.setType(OriginKeys.SAML);

        SamlIdentityProviderDefinition providerDefinition = new SamlIdentityProviderDefinition()
            .setMetaDataLocation(String.format(BootstrapSamlIdentityProviderConfiguratorTests.xmlWithoutID, "http://www.okta.com/" + identityProvider.getOriginKey()))
            .setIdpEntityAlias(identityProvider.getOriginKey())
            .setNameID("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
            .setLinkText("IDPEndpointsMockTests Saml Provider:" + identityProvider.getOriginKey())
            .setZoneId(IdentityZone.getUaa().getId());
        identityProvider.setConfig(providerDefinition);

        FieldDescriptor[] fieldDescriptors = {
            fieldWithPath("name").attributes(key("constraints").value("Required")).description(""),
            fieldWithPath("originKey").attributes(key("constraints").value("Required")).description(""),

            fieldWithPath("type").attributes(key("constraints").value("Optional")).description(""),
            fieldWithPath("id").attributes(key("constraints").value("Optional")).description(""),
            fieldWithPath("active").attributes(key("constraints").value("Optional")).description("Defaults to true."),
            fieldWithPath("version").attributes(key("constraints").value("Optional")).description(""),
            fieldWithPath("identityZoneId").attributes(key("constraints").value("Optional")).description(""),
            fieldWithPath("config").attributes(key("constraints").value("Optional")).description(""),

            fieldWithPath("config.idpEntityAlias").type(STRING).attributes(key("constraints").value("Required")).description("").optional(),
            fieldWithPath("config.zoneId").type(STRING).attributes(key("constraints").value("Required")).description("").optional(),
            fieldWithPath("config.metaDataLocation").type(STRING).attributes(key("constraints").value("Required")).description("").optional(),
            fieldWithPath("config.nameID").type(STRING).attributes(key("constraints").value("Optional")).description("").optional(),
            fieldWithPath("config.assertionConsumerIndex").type(NUMBER).attributes(key("constraints").value("Optional")).description("").optional(),
            fieldWithPath("config.metadataTrustCheck").type(BOOLEAN).attributes(key("constraints").value("Optional")).description("").optional(),
            fieldWithPath("config.showSamlLink").type(BOOLEAN).attributes(key("constraints").value("Optional")).description("").optional(),
            fieldWithPath("config.linkText").type(STRING).attributes(key("constraints").value("Optional")).description("").optional(),
            fieldWithPath("config.iconUrl").type(STRING).attributes(key("constraints").value("Optional")).description("").optional(),
            fieldWithPath("config.emailDomain").type(ARRAY).attributes(key("constraints").value("Optional")).description("").optional(),
            fieldWithPath("config.attributeMappings").type(OBJECT).attributes(key("constraints").value("Optional")).description("").optional(),
            fieldWithPath("config.attributeMappings.given_name").type(STRING).attributes(key("constraints").value("Optional")).description("").optional(),
            fieldWithPath("config.attributeMappings.family_name").type(STRING).attributes(key("constraints").value("Optional")).description("").optional(),
            fieldWithPath("config.attributeMappings.email").type(STRING).attributes(key("constraints").value("Optional")).description("").optional(),
            fieldWithPath("config.attributeMappings.phone_number").type(STRING).attributes(key("constraints").value("Optional")).description("").optional(),
            fieldWithPath("config.attributeMappings.external_groups").type(OBJECT).attributes(key("constraints").value("Optional")).description("").optional(),
            fieldWithPath("config.externalGroupsWhitelist").type(ARRAY).attributes(key("constraints").value("Optional")).description("").optional(),
            fieldWithPath("config.providerDescription").type(STRING).attributes(key("constraints").value("Optional")).description("").optional(),

            fieldWithPath("created").ignored(),
            fieldWithPath("last_modified").ignored()
        };

        ResultActions resultActions = getMockMvc().perform(post("/identity-providers")
            .header("Authorization", "Bearer " + adminToken)
            .contentType(APPLICATION_JSON)
            .content(JsonUtils.writeValueAsString(identityProvider)))
            .andExpect(status().isCreated());

        resultActions.andDo(document("{ClassName}/{methodName}",
            preprocessRequest(prettyPrint()),
            preprocessResponse(prettyPrint()),
            requestHeaders(
                headerWithName("Authorization").description("Bearer token containing `zones.read` or `zones.<zone id>.admin` or `zones.<zone id>.read`")
            ),
            requestFields(fieldDescriptors),
            responseFields(fieldDescriptors)
        ));
    }

    @Test
    public void createOAuthIdentityProvider() throws Exception {
        IdentityProvider identityProvider = new IdentityProvider();
        identityProvider.setType(OriginKeys.UAA);
        identityProvider.setName("UAA Provider");
        identityProvider.setOriginKey("OAUTH");
        identityProvider.setConfig(new RawXOAuthIdentityProviderDefinition());

        FieldDescriptor[] fieldDescriptors = {
            fieldWithPath("name").attributes(key("constraints").value("Required")).description(""),
            fieldWithPath("originKey").attributes(key("constraints").value("Required")).description(""),

            fieldWithPath("type").attributes(key("constraints").value("Optional")).description(""),
            fieldWithPath("id").attributes(key("constraints").value("Optional")).description(""),
            fieldWithPath("active").attributes(key("constraints").value("Optional")).description("Defaults to true."),
            fieldWithPath("version").attributes(key("constraints").value("Optional")).description(""),
            fieldWithPath("identityZoneId").attributes(key("constraints").value("Optional")).description(""),
            fieldWithPath("config").attributes(key("constraints").value("Optional")).description(""),

            fieldWithPath("config.alias").type(STRING).attributes(key("constraints").value("Required")).description("").optional(),
            fieldWithPath("config.authUrl").type(STRING).attributes(key("constraints").value("Required")).description("").optional(),
            fieldWithPath("config.tokenUrl").type(STRING).attributes(key("constraints").value("Required")).description("").optional(),
            fieldWithPath("config.type").type(STRING).attributes(key("constraints").value("Required")).description("").optional(),
            fieldWithPath("config.tokenKeyUrl").type(STRING).attributes(key("constraints").value("Optional")).description("").optional(),
            fieldWithPath("config.tokenKey").type(STRING).attributes(key("constraints").value("Optional")).description("").optional(),
            fieldWithPath("config.showLinkText").type(BOOLEAN).attributes(key("constraints").value("Optional")).description("").optional(),
            fieldWithPath("config.linkText").type(STRING).attributes(key("constraints").value("Optional")).description("").optional(),
            fieldWithPath("config.relyingPartyId").type(STRING).attributes(key("constraints").value("Required")).description("").optional(),
            fieldWithPath("config.relyingPartySecret").type(STRING).attributes(key("constraints").value("Required")).description("").optional(),
            fieldWithPath("config.skipSslValidation").type(BOOLEAN).attributes(key("constraints").value("Optional")).description("").optional(),
            fieldWithPath("config.attributeMappings").type(OBJECT).attributes(key("constraints").value("Optional")).description("").optional(),
            fieldWithPath("config.externalGroupsWhiteLists").type(ARRAY).attributes(key("constraints").value("Optional")).description("").optional(),
            fieldWithPath("config.providerDescription").type(STRING).attributes(key("constraints").value("Optional")).description("").optional(),


        fieldWithPath("created").ignored(),
            fieldWithPath("last_modified").ignored()
        };

        ResultActions resultActions = getMockMvc().perform(post("/identity-providers")
            .header("Authorization", "Bearer " + adminToken)
            .contentType(APPLICATION_JSON)
            .content(JsonUtils.writeValueAsString(identityProvider)))
            .andExpect(status().isCreated());

        resultActions.andDo(document("{ClassName}/{methodName}",
            preprocessRequest(prettyPrint()),
            preprocessResponse(prettyPrint()),
            requestHeaders(
                headerWithName("Authorization").description("Bearer token containing `zones.read` or `zones.<zone id>.admin` or `zones.<zone id>.read`")
            ),
            requestFields(fieldDescriptors),
            responseFields(fieldDescriptors)
        ));
    }

}
