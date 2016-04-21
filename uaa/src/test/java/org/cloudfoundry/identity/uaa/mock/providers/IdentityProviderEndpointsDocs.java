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
package org.cloudfoundry.identity.uaa.mock.providers;

import com.fasterxml.jackson.core.type.TypeReference;
import org.apache.commons.lang.ArrayUtils;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.provider.AbstractXOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.LockoutPolicy;
import org.cloudfoundry.identity.uaa.provider.RawXOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.saml.BootstrapSamlIdentityProviderConfiguratorTests;
import org.cloudfoundry.identity.uaa.test.SnippetUtils;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.restdocs.payload.FieldDescriptor;
import org.springframework.restdocs.snippet.Snippet;
import org.springframework.test.web.servlet.ResultActions;

import java.net.URL;
import java.util.HashMap;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OAUTH20;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OIDC10;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.SAML;
import static org.cloudfoundry.identity.uaa.test.SnippetUtils.fieldWithPath;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.restdocs.headers.HeaderDocumentation.headerWithName;
import static org.springframework.restdocs.headers.HeaderDocumentation.requestHeaders;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.delete;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.get;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.post;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.put;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.preprocessRequest;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.preprocessResponse;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.prettyPrint;
import static org.springframework.restdocs.payload.JsonFieldType.ARRAY;
import static org.springframework.restdocs.payload.JsonFieldType.BOOLEAN;
import static org.springframework.restdocs.payload.JsonFieldType.NUMBER;
import static org.springframework.restdocs.payload.JsonFieldType.OBJECT;
import static org.springframework.restdocs.payload.JsonFieldType.STRING;
import static org.springframework.restdocs.payload.PayloadDocumentation.requestFields;
import static org.springframework.restdocs.payload.PayloadDocumentation.responseFields;
import static org.springframework.restdocs.request.RequestDocumentation.parameterWithName;
import static org.springframework.restdocs.request.RequestDocumentation.pathParameters;
import static org.springframework.restdocs.snippet.Attributes.key;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class IdentityProviderEndpointsDocs extends InjectedMockContextTest {
	private static final String NAME_DESC = "Human-readable name for this provider";
	private static final String VERSION_DESC = "Version of the identity provider data. Clients can use this to protect against conflicting updates";
	private static final String ACTIVE_DESC = "Defaults to true.";
	private static final String ID_DESC = "Unique identifier for this provider - GUID generated by the UAA";
	private static final String IDENTITY_ZONE_ID_DESC = "Set to the zone that this provider will be active in. Determined either by the Host header or the zone switch header.";
	private static final String CREATED_DESC = "UAA sets the creation date";
	private static final String LAST_MODIFIED_DESC = "UAA sets the modification date";
    private static final String CONFIG_DESCRIPTION = "Json config for the Identity Provider";
    private static final FieldDescriptor ATTRIBUTE_MAPPING = fieldWithPath("config.attributeMappings.given_name").optional(null).type(STRING).description("Map `given_name` to the attribute for given name in the provider assertion.").optional();
    private static final FieldDescriptor GIVEN_NAME = fieldWithPath("config.attributeMappings.given_name").optional(null).type(STRING).description("Map `given_name` to the attribute for given name in the provider assertion.").optional();
    private TestClient testClient = null;
    private String adminToken;
    private IdentityProviderProvisioning identityProviderProvisioning;

    private FieldDescriptor FAMILY_NAME = fieldWithPath("config.attributeMappings.family_name").optional(null).type(STRING).description("Map `family_name` to the attribute for family name in the provider assertion.").optional();
    private FieldDescriptor EMAIL = fieldWithPath("config.attributeMappings.email").optional(null).type(STRING).description("Map `email` to the attribute for email in the provider assertion.").optional();
    private FieldDescriptor PHONE_NUMBER = fieldWithPath("config.attributeMappings.phone_number").optional(null).type(STRING).description("Map `phone_number` to the attribute for phone number in the provider assertion.").optional();
    private FieldDescriptor EXTERNAL_GROUPS = fieldWithPath("config.attributeMappings.external_groups").optional(null).type(OBJECT).description("Map `external_groups` to the attribute for groups in the provider assertion.").optional();
    private FieldDescriptor EXTERNAL_GROUPS_WHITELIST = fieldWithPath("config.externalGroupsWhitelist").optional(null).type(ARRAY).description("List of external groups that will be included in the ID Token if the `roles` scope is requested.").optional();
    private FieldDescriptor PROVIDER_DESC = fieldWithPath("config.providerDescription").optional(null).type(STRING).description("Human readable name/description of this provider").optional();
    private FieldDescriptor EMAIL_DOMAIN = fieldWithPath("config.emailDomain").optional(null).type(ARRAY).description("List of email domains associated with the provider for the purpose of associating users to the correct origin upon invitation. If empty list, no invitations are accepted. Wildcards supported.").optional();
    private FieldDescriptor ACTIVE = fieldWithPath("active").optional(null).description(ACTIVE_DESC);
    private FieldDescriptor NAME = fieldWithPath("name").required().description(NAME_DESC);
    private FieldDescriptor CONFIG = fieldWithPath("config").required().description("Json config for the provider");

    private SnippetUtils.ConstrainableField VERSION = (SnippetUtils.ConstrainableField) fieldWithPath("version").type(NUMBER).description(VERSION_DESC);
    private FieldDescriptor ID = fieldWithPath("id").type(STRING).description(ID_DESC);
    private FieldDescriptor CREATED = fieldWithPath("created").description(CREATED_DESC);
    private FieldDescriptor LAST_MODIFIED = fieldWithPath("last_modified").description(LAST_MODIFIED_DESC);
    private FieldDescriptor IDENTITY_ZONE_ID = fieldWithPath("identityZoneId").type(STRING).description(IDENTITY_ZONE_ID_DESC);

    @Before
    public void setUp() throws Exception {
        testClient = new TestClient(getMockMvc());
        adminToken = testClient.getClientCredentialsOAuthAccessToken(
            "admin",
            "adminsecret",
            "");

        identityProviderProvisioning = getWebApplicationContext().getBean(IdentityProviderProvisioning.class);
    }

    @After
    public void clearUaaConfig() throws Exception {
        getWebApplicationContext().getBean(JdbcTemplate.class).update("UPDATE identity_provider SET config=null WHERE origin_key='uaa'");
    }

    private static String serializeExcludingProperties(Object object, String... propertiesToExclude) {
        String serialized = JsonUtils.writeValueAsString(object);
        Map<String, Object> properties = JsonUtils.readValue(serialized, new TypeReference<Map<String, Object>>() {});
        for(String property : propertiesToExclude) {
            if(property.contains(".")) {
                String[] split = property.split("\\.", 2);
                if(properties.containsKey(split[0])) {
                    Object inner = properties.get(split[0]);
                    properties.put(split[0], JsonUtils.readValue(serializeExcludingProperties(inner, split[1]), new TypeReference<Map<String, Object>>() {}));
                }
            } else {
                properties.remove(property);
            }
        }
        return JsonUtils.writeValueAsString(properties);
    }

    @Test
    public void createSAMLIdentityProvider() throws Exception {
        IdentityProvider identityProvider = getSamlProvider("SAML");
        identityProvider.setSerializeConfigRaw(true);

        FieldDescriptor[] idempotentFields = (FieldDescriptor[]) ArrayUtils.addAll(commonProviderFields, new FieldDescriptor[]{
            fieldWithPath("type").required().description("`saml`"),
            fieldWithPath("originKey").required().description("A unique alias for the SAML provider"),
            fieldWithPath("config.metaDataLocation").required().type(STRING).description("SAML Metadata - either an XML string or a URL that will deliver XML content"),
            fieldWithPath("config.nameID").optional(null).type(STRING).description("The name ID to use for the username, default is \"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified\". Currently the UAA expects the username to be a valid email address"),
            fieldWithPath("config.assertionConsumerIndex").optional(null).type(NUMBER).description("SAML assertion consumer index, default is 0"),
            fieldWithPath("config.metadataTrustCheck").optional(null).type(BOOLEAN).description("Should metadata be validated, defaults to false"),
            fieldWithPath("config.showSamlLink").optional(null).type(BOOLEAN).description("Should the SAML login link be displayed on the login page, defaults to false"),
            fieldWithPath("config.linkText").type(STRING).attributes(key("constraints").value("Required if the ``showSamlLink`` is set to true")).description("The link text for the SAML IDP on the login page"),
            fieldWithPath("config.groupMappingMode").optional(null).type(STRING).description("Either ``EXPLICITLY_MAPPED`` in order to map external groups to OAuth scopes using the group mappings, or ``AS_SCOPES`` to use SAML group names as scopes."),
            fieldWithPath("config.iconUrl").optional(null).type(STRING).description("Reserved for future use"),
            fieldWithPath("config.additionalConfiguration").optional(null).type(OBJECT).description("Further configuration attributes"),
            fieldWithPath("config.attributeMappings").optional(new HashMap()).type(OBJECT).description("Further configuration attributes")
        });
        Snippet requestFields = requestFields(idempotentFields);

        Snippet responseFields = responseFields((FieldDescriptor[]) ArrayUtils.addAll(idempotentFields, new FieldDescriptor[]{
            VERSION,
            ID,
            IDENTITY_ZONE_ID,
            CREATED,
            LAST_MODIFIED,
            fieldWithPath("config.idpEntityAlias").type(STRING).description("This will be set to ``originKey``").optional(),
            fieldWithPath("config.zoneId").type(STRING).description("This will be set to the ID of the zone where the provider is being created").optional()
        }));

        ResultActions resultActions = getMockMvc().perform(post("/identity-providers")
            .param("rawConfig", "true")
            .header("Authorization", "Bearer " + adminToken)
            .contentType(APPLICATION_JSON)
            .content(serializeExcludingProperties(identityProvider, "id", "version", "created", "last_modified", "identityZoneId", "config.zoneId", "config.idpEntityAlias")))
            .andExpect(status().isCreated());

        resultActions.andDo(document("{ClassName}/{methodName}",
            preprocessRequest(prettyPrint()),
            preprocessResponse(prettyPrint()),
            requestHeaders(
                headerWithName("Authorization").description("Bearer token containing `zones.<zone id>.admin` or `uaa.admin` or `idps.write` (only in the same zone that you are a user of)"),
                headerWithName("X-Identity-Zone-Id").description("May include this header to administer another zone if using `zones.<zone id>.admin` or `uaa.admin` scope against the default UAA zone.").optional()
            ),
            requestFields,
            responseFields
        ));
    }

    @Test
    public void createOAuthIdentityProvider() throws Exception {
        IdentityProvider identityProvider = new IdentityProvider();
        identityProvider.setType(OAUTH20);
        identityProvider.setName("UAA Provider");
        identityProvider.setOriginKey(OAUTH20);
        AbstractXOAuthIdentityProviderDefinition definition = new RawXOAuthIdentityProviderDefinition();
        definition.setAuthUrl(new URL("http://auth.url"));
        definition.setTokenUrl(new URL("http://token.url"));
        definition.setTokenKey("token-key");
        definition.setRelyingPartyId("uaa");
        definition.setRelyingPartySecret("secret");
        definition.setShowLinkText(false);
        identityProvider.setConfig(definition);
        identityProvider.setSerializeConfigRaw(true);

        FieldDescriptor[] idempotentFields = (FieldDescriptor[]) ArrayUtils.addAll(commonProviderFields, new FieldDescriptor[]{
            fieldWithPath("type").required().description("`\""+OAUTH20+"\"` or `\""+OIDC10+"\"`"),
            fieldWithPath("originKey").required().description("A unique alias for a OAuth provider"),
            fieldWithPath("config.alias").required().type(STRING).description("A unique alias for referring to this identity provider").optional(),
            fieldWithPath("config.authUrl").required().type(STRING).description("The OAuth 2.0 authorization endpoint URL").optional(),
            fieldWithPath("config.tokenUrl").required().type(STRING).description("The OAuth 2.0 token endpoint URL").optional(),
            fieldWithPath("config.tokenKeyUrl").optional(null).type(STRING).description("The URL of the token key endpoint which renders a verification key for validating token signatures").optional(),
            fieldWithPath("config.tokenKey").optional(null).type(STRING).description("A verification key for validating token signatures").optional(),
            fieldWithPath("config.showLinkText").optional(true).type(BOOLEAN).description("A flag controlling whether a link to this provider's login will be shown on the UAA login page").optional(),
            fieldWithPath("config.linkText").optional(null).type(STRING).description("Text to use for the login link to the provider").optional(),
            fieldWithPath("config.relyingPartyId").required().type(STRING).description("The client ID which is registered with the external OAuth provider for use by the UAA").optional(),
            fieldWithPath("config.relyingPartySecret").required().type(STRING).description("The client secret of the relying party at the external OAuth provider").optional(),
            fieldWithPath("config.skipSslValidation").optional(null).type(BOOLEAN).description("A flag controlling whether SSL validation should be skipped when communicating with the external OAuth server").optional(),
            fieldWithPath("config.attributeMappings").optional(null).type(OBJECT).description("Mappings from external token claims").optional(),
            fieldWithPath("config.externalGroupsWhiteLists").optional(null).type(ARRAY).description("Groups which the UAA may map from external roles from this identity provider").optional(),
        });
        Snippet requestFields = requestFields(idempotentFields);

        Snippet responseFields = responseFields((FieldDescriptor[]) ArrayUtils.addAll(idempotentFields, new FieldDescriptor[]{
            VERSION,
            ID,
            IDENTITY_ZONE_ID,
            CREATED,
            LAST_MODIFIED
        }));

        ResultActions resultActions = getMockMvc().perform(post("/identity-providers")
            .param("rawConfig", "true")
            .header("Authorization", "Bearer " + adminToken)
            .contentType(APPLICATION_JSON)
            .content(serializeExcludingProperties(identityProvider, "id", "version", "created", "last_modified", "identityZoneId")))
            .andExpect(status().isCreated());

        resultActions.andDo(document("{ClassName}/{methodName}",
            preprocessRequest(prettyPrint()),
            preprocessResponse(prettyPrint()),
            requestHeaders(
                headerWithName("Authorization").description("Bearer token containing `zones.<zone id>.admin` or `uaa.admin` or `idps.write` (only in the same zone that you are a user of)"),
                headerWithName("X-Identity-Zone-Id").description("May include this header to administer another zone if using `zones.<zone id>.admin` or `uaa.admin` scope against the default UAA zone.").optional()
            ),
            requestFields,
            responseFields
        ));
    }
    
    @Test
    public void createLDAPIdentityProvider() throws Exception {
        IdentityZone ldapZone = MockMvcUtils.utils().createZoneUsingWebRequest(getMockMvc(), adminToken);
        IdentityProvider identityProvider = MultitenancyFixture.identityProvider("LDAP", ldapZone.getId());
        identityProvider.setType(OriginKeys.LDAP);

        LdapIdentityProviderDefinition providerDefinition = new LdapIdentityProviderDefinition();
        providerDefinition.setLdapProfileFile("ldap/ldap-search-and-bind.xml");
        providerDefinition.setLdapGroupFile("ldap/ldap-groups-map-to-scopes.xml");
        providerDefinition.setBaseUrl("ldap://base.url");
        providerDefinition.setBindUserDn("CN=Administrator,CN=Users,DC=ad");
        providerDefinition.setBindPassword("password");
        providerDefinition.setUserSearchBase("CN=Users,DC=Org,DC=my-domain,DC=com");
        providerDefinition.setUserSearchFilter("(&amp;(anAttribute={0})(objectclass=user))");
        providerDefinition.setGroupSearchBase("OU=Groups,DC=Org,DC=my-domain,DC=com");
        providerDefinition.setGroupSearchFilter("memberOf={0}");
        providerDefinition.setMailAttributeName("mail");
        providerDefinition.setAutoAddGroups(true);
        providerDefinition.setGroupSearchSubTree(true);
        providerDefinition.setMaxGroupSearchDepth(3);
        identityProvider.setConfig(providerDefinition);
        identityProvider.setSerializeConfigRaw(true);

        FieldDescriptor[] idempotentFields = (FieldDescriptor[]) ArrayUtils.addAll(commonProviderFields, new FieldDescriptor[]{
            fieldWithPath("type").required().description("`ldap`"),
            fieldWithPath("originKey").required().description("Origin key must be `ldap` for an LDAP provider"),
            fieldWithPath("config.ldapProfileFile").required().type(STRING).description("The file to be used for configuring the LDAP authentication. Options are: 'ldap/ldap-simple-bind.xml', 'ldap/ldap-search-and-bind.xml', 'ldap/ldap-search-and-compare.xml'").optional(),
            fieldWithPath("config.ldapGroupFile").required().type(STRING).description("The file to be used for group integration. Options are: 'ldap/ldap-no-groups.xml', 'ldap/ldap-groups-as-scopes.xml', 'ldap/ldap-groups-map-to-scopes.xml'").optional(),
            fieldWithPath("config.baseUrl").required().type(STRING).description("The URL to the ldap server, must start with ldap:// or ldaps://").optional(),
            fieldWithPath("config.bindUserDn").required().type(STRING).description("Used with search-and-bind and search-and-compare. A valid LDAP ID that has read permissions to perform a search of the LDAP tree for user information.").optional(),
            fieldWithPath("config.bindPassword").required().type(STRING).description("Used with search-and-bind and search-and-compare. Password for the LDAP ID that performs a search of the LDAP tree for user information.").optional(),
            fieldWithPath("config.userSearchBase").required().type(STRING).description("Used with search-and-bind and search-and-compare. Define a base where the search starts at.").optional(),
            fieldWithPath("config.userSearchFilter").required().type(STRING).description("Used with search-and-bind and search-and-compare. Search filter used. Takes one parameter, user ID defined as {0}").optional(),
            fieldWithPath("config.groupSearchBase").required().type(STRING).description("Search start point for a user group membership search").optional(),
            fieldWithPath("config.groupSearchFilter").required().type(STRING).description("Search query filter to find the groups a user belongs to, or for a nested search, groups that a group belongs to").optional(),
            fieldWithPath("config.mailAttributeName").required().type(STRING).description("The name of the LDAP attribute that contains the users email address").optional(),
            fieldWithPath("config.autoAddGroups").required().type(BOOLEAN).description("Set to true when profile_type=groups_as_scopes to auto create scopes for a user. Ignored for other profiles.").optional(),
            fieldWithPath("config.groupSearchSubTree").required().type(BOOLEAN).description("Boolean value, set to true to search below the search base").optional(),
            fieldWithPath("config.groupMaxSearchDepth").required().type(NUMBER).description("Set to number of levels a nested group search should go. Set to 1 to disable nested groups (default)").optional(),
            fieldWithPath("config.mailSubstitute").optional(null).type(STRING).description("Defines an email pattern containing a {0} to generate an email address for an LDAP user during authentication").optional(),
            fieldWithPath("config.mailSubstituteOverridesLdap").optional(null).type(BOOLEAN).description("Set to true if you wish to override an LDAP user email address with a generated one").optional(),
            fieldWithPath("config.skipSSLVerification").optional(null).type(BOOLEAN).description("Skips validation of the LDAP cert if set to true.").optional()
        });
        Snippet requestFields = requestFields(idempotentFields);

        Snippet responseFields = responseFields((FieldDescriptor[]) ArrayUtils.addAll(idempotentFields, new FieldDescriptor[]{
            VERSION,
            ID,
            IDENTITY_ZONE_ID,
            CREATED,
            LAST_MODIFIED
        }));

        ResultActions resultActions = getMockMvc().perform(post("/identity-providers")
            .param("rawConfig", "true")
            .header("Authorization", "Bearer " + adminToken)
            .contentType(APPLICATION_JSON)
            .content(serializeExcludingProperties(identityProvider, "id", "version", "created", "last_modified", "identityZoneId")))
            .andExpect(status().isCreated());

        resultActions.andDo(document("{ClassName}/{methodName}",
            preprocessRequest(prettyPrint()),
            preprocessResponse(prettyPrint()),
            requestHeaders(
                headerWithName("Authorization").description("Bearer token containing `zones.<zone id>.admin` or `uaa.admin` or `idps.write` (only in the same zone that you are a user of)"),
                headerWithName("X-Identity-Zone-Id").description("May include this header to administer another zone if using `zones.<zone id>.admin` or `uaa.admin` scope against the default UAA zone.").optional()
            ),
            requestFields,
            responseFields
        ));
    }

    @Test
    public void getAllIdentityProviders() throws Exception {
        Snippet responseFields = responseFields(
            fieldWithPath("[].type").description("Type of the identity provider."),
            fieldWithPath("[].originKey").description("Unique identifier for the identity provider."),
            fieldWithPath("[].name").description(NAME_DESC),
            fieldWithPath("[].config").description(CONFIG_DESCRIPTION),

            fieldWithPath("[].version").description(VERSION_DESC),
            fieldWithPath("[].active").description(ACTIVE_DESC),

            fieldWithPath("[].id").description(ID_DESC),
            fieldWithPath("[].identityZoneId").description(IDENTITY_ZONE_ID_DESC),
            fieldWithPath("[].created").description(CREATED_DESC),
            fieldWithPath("[].last_modified").description(LAST_MODIFIED_DESC)
        );

        getMockMvc().perform(get("/identity-providers")
            .param("rawConfig", "true")
            .header("Authorization", "Bearer " + adminToken)
            .contentType(APPLICATION_JSON))
            .andExpect(status().isOk())
            .andDo(document("{ClassName}/{methodName}",
                preprocessResponse(prettyPrint()),
                requestHeaders(
                    headerWithName("Authorization").description("Bearer token containing `zones.<zone id>.admin` or `zones.<zone id>.idps.read` or `uaa.admin` or `idps.read` (only in the same zone that you are a user of)"),
                    headerWithName("X-Identity-Zone-Id").description("May include this header to administer another zone if using `zones.<zone id>.admin` or `zones.<zone id>.idps.read` or `uaa.admin` scope against the default UAA zone.").optional()
                ),
                responseFields));
    }

    @Test
    public void getIdentityProvider() throws Exception {
        IdentityProvider identityProvider = JsonUtils.readValue(getMockMvc().perform(post("/identity-providers")
            .header("Authorization", "Bearer " + adminToken)
            .contentType(APPLICATION_JSON)
            .content(JsonUtils.writeValueAsString(getSamlProvider("saml-for-get"))))
            .andExpect(status().isCreated())
            .andReturn().getResponse().getContentAsString(), IdentityProvider.class);

        getMockMvc().perform(get("/identity-providers/{id}", identityProvider.getId())
            .header("Authorization", "Bearer " + adminToken)
            .contentType(APPLICATION_JSON))
            .andExpect(status().isOk())
            .andDo(document("{ClassName}/{methodName}",
                preprocessResponse(prettyPrint()),
                pathParameters(
                    parameterWithName("id").description(ID_DESC)
                ),
                requestHeaders(
                    headerWithName("Authorization").description("Bearer token containing `zones.<zone id>.admin` or `zones.<zone id>.idps.read` or `uaa.admin` or `idps.read` (only in the same zone that you are a user of)"),
                    headerWithName("X-Identity-Zone-Id").description("May include this header to administer another zone if using `zones.<zone id>.admin` or `zones.<zone id>.idps.read` or `uaa.admin` scope against the default UAA zone.").optional()
                ),
                responseFields(getCommonProviderFieldsAnyType())));

        deleteIdentityProviderHelper(identityProvider.getId());
    }

    @Test
    public void updateIdentityProvider() throws Exception {
        IdentityProvider identityProvider = identityProviderProvisioning.retrieveByOrigin(OriginKeys.UAA, IdentityZoneHolder.get().getId());

        UaaIdentityProviderDefinition config = new UaaIdentityProviderDefinition();
        config.setLockoutPolicy(new LockoutPolicy(8, 8, 8));
        identityProvider.setConfig(config);
        identityProvider.setSerializeConfigRaw(true);

        FieldDescriptor[] idempotentFields = (FieldDescriptor[]) ArrayUtils.addAll(commonProviderFields, new FieldDescriptor[]{
            fieldWithPath("type").required().description("`uaa`"),
            fieldWithPath("originKey").required().description("A unique identifier for the IDP. Cannot be updated."),
            VERSION.required(),
            fieldWithPath("config.passwordPolicy.minLength").type(NUMBER).attributes(key("constraints").value("Required when `passwordPolicy` in the config is not null")).description("Minimum number of characters required for password to be considered valid (defaults to 0).").optional(),
            fieldWithPath("config.passwordPolicy.maxLength").type(NUMBER).attributes(key("constraints").value("Required when `passwordPolicy` in the config is not null")).description("Maximum number of characters required for password to be considered valid (defaults to 255).").optional(),
            fieldWithPath("config.passwordPolicy.requireUpperCaseCharacter").type(NUMBER).attributes(key("constraints").value("Required when `passwordPolicy` in the config is not null")).description("Minimum number of uppercase characters required for password to be considered valid (defaults to 0).").optional(),
            fieldWithPath("config.passwordPolicy.requireLowerCaseCharacter").type(NUMBER).attributes(key("constraints").value("Required when `passwordPolicy` in the config is not null")).description("Minimum number of lowercase characters required for password to be considered valid (defaults to 0).").optional(),
            fieldWithPath("config.passwordPolicy.requireDigit").type(NUMBER).attributes(key("constraints").value("Required when `passwordPolicy` in the config is not null")).description("Minimum number of digits required for password to be considered valid (defaults to 0).").optional(),
            fieldWithPath("config.passwordPolicy.requireSpecialCharacter").type(NUMBER).attributes(key("constraints").value("Required when `passwordPolicy` in the config is not null")).description("Minimum number of special characters required for password to be considered valid (defaults to 0).").optional(),
            fieldWithPath("config.passwordPolicy.expirePasswordInMonths").type(NUMBER).attributes(key("constraints").value("Required when `passwordPolicy` in the config is not null")).description("Number of months after which current password expires (defaults to 0).").optional(),
            fieldWithPath("config.lockoutPolicy.lockoutPeriodSeconds").type(NUMBER).attributes(key("constraints").value("Required when `LockoutPolicy` in the config is not null")).description("Number of allowed failures before account is locked (defaults to 5).").optional(),
            fieldWithPath("config.lockoutPolicy.lockoutAfterFailures").type(NUMBER).attributes(key("constraints").value("Required when `LockoutPolicy` in the config is not null")).description("Number of seconds in which lockoutAfterFailures failures must occur in order for account to be locked (defaults to 3600).").optional(),
            fieldWithPath("config.lockoutPolicy.countFailuresWithin").type(NUMBER).attributes(key("constraints").value("Required when `LockoutPolicy` in the config is not null")).description("Number of seconds to lock out an account when lockoutAfterFailures failures is exceeded (defaults to 300).").optional(),
            fieldWithPath("config.disableInternalUserManagement").optional(null).type(BOOLEAN).description("When set to true, user management is disabled for this provider, defaults to false").optional()
        });
        Snippet requestFields = requestFields(idempotentFields);

        Snippet responseFields = responseFields((FieldDescriptor[]) ArrayUtils.addAll(idempotentFields, new FieldDescriptor[]{
            VERSION,
            ID,
            IDENTITY_ZONE_ID,
            CREATED,
            LAST_MODIFIED,
        }));

        getMockMvc().perform(put("/identity-providers/{id}", identityProvider.getId())
            .header("Authorization", "Bearer " + adminToken)
            .contentType(APPLICATION_JSON)
            .content(serializeExcludingProperties(identityProvider, "id", "created", "last_modified", "identityZoneId")))
            .andExpect(status().isOk())
            .andDo(document("{ClassName}/{methodName}",
                preprocessResponse(prettyPrint()),
                pathParameters(
                    parameterWithName("id").description(ID_DESC)
                ),
                requestHeaders(
                    headerWithName("Authorization").description("Bearer token containing `zones.<zone id>.admin` or `uaa.admin` or `idps.write` (only in the same zone that you are a user of)"),
                    headerWithName("X-Identity-Zone-Id").description("May include this header to administer another zone if using `zones.<zone id>.admin` or `uaa.admin` scope against the default UAA zone.").optional()
                ),
                requestFields,
                responseFields));
    }

    @Test
    public void deleteIdentityProvider() throws Exception {
        IdentityProvider identityProvider = JsonUtils.readValue(getMockMvc().perform(post("/identity-providers")
            .header("Authorization", "Bearer " + adminToken)
            .contentType(APPLICATION_JSON)
            .content(JsonUtils.writeValueAsString(getSamlProvider("saml-for-delete"))))
            .andExpect(status().isCreated())
            .andReturn().getResponse().getContentAsString(), IdentityProvider.class);

        ResultActions resultActions = deleteIdentityProviderHelper(identityProvider.getId());

        resultActions
            .andDo(document("{ClassName}/{methodName}",
                preprocessResponse(prettyPrint()),
                pathParameters(
                    parameterWithName("id").description(ID_DESC)
                ),
                requestHeaders(
                    headerWithName("Authorization").description("Bearer token containing `zones.<zone id>.admin` or `uaa.admin` or `idps.write` (only in the same zone that you are a user of)"),
                    headerWithName("X-Identity-Zone-Id").description("May include this header to administer another zone if using `zones.<zone id>.admin` or `uaa.admin` scope against the default UAA zone.").optional()
                ),
                responseFields(getCommonProviderFieldsAnyType())));
    }

    private ResultActions deleteIdentityProviderHelper(String id) throws Exception {
        return getMockMvc().perform(delete("/identity-providers/{id}", id)
            .header("Authorization", "Bearer " + adminToken)
            .contentType(APPLICATION_JSON))
            .andExpect(status().isOk());
    }

    private FieldDescriptor[] getCommonProviderFieldsAnyType() {
        return (FieldDescriptor[]) ArrayUtils.addAll(commonProviderFields, new FieldDescriptor[]{
            fieldWithPath("type").required().description("Type of the identity provider."),
            fieldWithPath("originKey").required().description("Unique identifier for the identity provider."),
            VERSION,
            ID,
            IDENTITY_ZONE_ID,
            CREATED,
            LAST_MODIFIED
        });
    }

    private FieldDescriptor[] commonProviderFields = {
        NAME,
        PROVIDER_DESC,
        EMAIL_DOMAIN,
        ATTRIBUTE_MAPPING,
        GIVEN_NAME,
        FAMILY_NAME,
        EMAIL,
        PHONE_NUMBER,
        EXTERNAL_GROUPS,
        EXTERNAL_GROUPS_WHITELIST,
        ACTIVE
    };

    private IdentityProvider getSamlProvider(String originKey) {
        IdentityProvider<SamlIdentityProviderDefinition> identityProvider = MultitenancyFixture.identityProvider(originKey, IdentityZone.getUaa().getId());
        identityProvider.setType(SAML);

        SamlIdentityProviderDefinition providerDefinition = new SamlIdentityProviderDefinition()
            .setMetaDataLocation(String.format(BootstrapSamlIdentityProviderConfiguratorTests.xmlWithoutID, "http://www.okta.com/" + identityProvider.getOriginKey()))
            .setIdpEntityAlias(identityProvider.getOriginKey())
            .setNameID("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
            .setLinkText("IDPEndpointsMockTests Saml Provider:" + identityProvider.getOriginKey())
            .setZoneId(IdentityZone.getUaa().getId());
        identityProvider.setConfig(providerDefinition);
        return identityProvider;
    }
}
