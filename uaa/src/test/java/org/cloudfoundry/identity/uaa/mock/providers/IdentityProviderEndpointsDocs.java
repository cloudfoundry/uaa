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

import org.apache.commons.lang.ArrayUtils;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.mock.util.ApacheDSHelper;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.IdentityZoneCreationResult;
import org.cloudfoundry.identity.uaa.provider.AbstractXOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderStatus;
import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.LockoutPolicy;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.PasswordPolicy;
import org.cloudfoundry.identity.uaa.provider.RawXOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.ldap.DynamicPasswordComparator;
import org.cloudfoundry.identity.uaa.provider.saml.BootstrapSamlIdentityProviderConfiguratorTests;
import org.cloudfoundry.identity.uaa.test.SnippetUtils;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.restdocs.payload.FieldDescriptor;
import org.springframework.restdocs.snippet.Attributes;
import org.springframework.restdocs.snippet.Snippet;
import org.springframework.security.ldap.server.ApacheDsSSLContainer;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.test.web.servlet.ResultActions;

import java.net.URL;

import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LDAP;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OAUTH20;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OIDC10;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.SAML;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.CookieCsrfPostProcessor.cookieCsrf;
import static org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition.MAIL;
import static org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition.ExternalGroupMappingMode.EXPLICITLY_MAPPED;
import static org.cloudfoundry.identity.uaa.test.SnippetUtils.fieldWithPath;
import static org.cloudfoundry.identity.uaa.test.SnippetUtils.parameterWithName;
import static org.cloudfoundry.identity.uaa.util.JsonUtils.serializeExcludingProperties;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.restdocs.headers.HeaderDocumentation.headerWithName;
import static org.springframework.restdocs.headers.HeaderDocumentation.requestHeaders;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.delete;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.get;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.patch;
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
import static org.springframework.restdocs.request.RequestDocumentation.pathParameters;
import static org.springframework.restdocs.request.RequestDocumentation.requestParameters;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
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
    private static final String FAMILY_NAME_DESC = "Map `family_name` to the attribute for family name in the provider assertion.";
    private static final String PHONE_NUMBER_DESC = "Map `phone_number` to the attribute for phone number in the provider assertion.";
    private static final String GIVEN_NAME_DESC = "Map `given_name` to the attribute for given name in the provider assertion.";

    private static final FieldDescriptor STORE_CUSTOM_ATTRIBUTES = fieldWithPath("config.storeCustomAttributes").optional(false).type(BOOLEAN).description("Set to true, to store custom user attributes to be fetched from the /userinfo endpoint");
    private static final FieldDescriptor SKIP_SSL_VALIDATION = fieldWithPath("config.skipSslValidation").optional(false).type(BOOLEAN).description("Set to true, to skip SSL validation when fetching metadata.");
    private static final FieldDescriptor ATTRIBUTE_MAPPING = fieldWithPath("config.attributeMappings").optional(null).type(OBJECT).description("Map external attribute to UAA recognized mappings.");
    private static final FieldDescriptor ADD_SHADOW_USER = fieldWithPath("config.addShadowUserOnLogin").optional(true).type(BOOLEAN).description("Whether users should be allowed to authenticate from LDAP without having a user pre-populated in the users database");
    private static final FieldDescriptor GIVEN_NAME = fieldWithPath("config.attributeMappings.given_name").optional(null).type(STRING).description(GIVEN_NAME_DESC);
    private static final FieldDescriptor FAMILY_NAME = fieldWithPath("config.attributeMappings.family_name").optional(null).type(STRING).description(FAMILY_NAME_DESC);
    private static final FieldDescriptor EMAIL = fieldWithPath("config.attributeMappings.email").optional(null).type(STRING).description("Map `email` to the attribute for email in the provider assertion.");
    private static final FieldDescriptor PHONE_NUMBER = fieldWithPath("config.attributeMappings.phone_number").optional(null).type(STRING).description(PHONE_NUMBER_DESC);
    private static final FieldDescriptor EXTERNAL_GROUPS = fieldWithPath("config.attributeMappings.external_groups").optional(null).type(OBJECT).description("Map `external_groups` to the attribute for groups in the provider assertion.");
    private static final FieldDescriptor EXTERNAL_GROUPS_WHITELIST = fieldWithPath("config.externalGroupsWhitelist").optional(null).type(ARRAY).description("List of external groups that will be included in the ID Token if the `roles` scope is requested.");
    private static final FieldDescriptor PROVIDER_DESC = fieldWithPath("config.providerDescription").optional(null).type(STRING).description("Human readable name/description of this provider");
    private static final FieldDescriptor EMAIL_DOMAIN = fieldWithPath("config.emailDomain").optional(null).type(ARRAY).description("List of email domains associated with the provider for the purpose of associating users to the correct origin upon invitation. If empty list, no invitations are accepted. Wildcards supported.");
    private static final FieldDescriptor ACTIVE = fieldWithPath("active").optional(null).description(ACTIVE_DESC);
    private static final FieldDescriptor NAME = fieldWithPath("name").required().description(NAME_DESC);
    private static final FieldDescriptor CONFIG = fieldWithPath("config").required().description("Various configuration properties for the identity provider.");
    private static final FieldDescriptor ADD_SHADOW_USER_ON_LOGIN = fieldWithPath("config.addShadowUserOnLogin").optional(true).description("Determines whether or not shadow users must be created before login by an administrator.");
    private static final FieldDescriptor ID = fieldWithPath("id").type(STRING).description(ID_DESC);
    private static final FieldDescriptor CREATED = fieldWithPath("created").description(CREATED_DESC);
    private static final FieldDescriptor LAST_MODIFIED = fieldWithPath("last_modified").description(LAST_MODIFIED_DESC);
    private static final FieldDescriptor IDENTITY_ZONE_ID = fieldWithPath("identityZoneId").type(STRING).description(IDENTITY_ZONE_ID_DESC);
    private static final FieldDescriptor ADDITIONAL_CONFIGURATION = fieldWithPath("config.additionalConfiguration").optional(null).type(OBJECT).description("(Unused.)");
    private static final SnippetUtils.ConstrainableField VERSION = (SnippetUtils.ConstrainableField) fieldWithPath("version").type(NUMBER).description(VERSION_DESC);
    private static final Snippet commonRequestParams = requestParameters(parameterWithName("rawConfig").optional("false").type(BOOLEAN).description("<small><mark>UAA 3.4.0</mark></small> Flag indicating whether the response should use raw, unescaped JSON for the `config` field of the IDP, rather than the default behavior of encoding the JSON as a string."));

    private static final int LDAP_PORT = 23389;
    private static final int LDAPS_PORT = 23636;
    private final String ldapServerUrl = "ldap://localhost:"+LDAP_PORT;


    private String adminToken;
    private IdentityProviderProvisioning identityProviderProvisioning;

    private FieldDescriptor[] commonProviderFields = {
        NAME,
        PROVIDER_DESC,
        EMAIL_DOMAIN,
        ACTIVE,
        ADD_SHADOW_USER,
        STORE_CUSTOM_ATTRIBUTES
    };

    FieldDescriptor relayingPartySecret = fieldWithPath("config.relyingPartySecret").required().type(STRING).description("The client secret of the relying party at the external OAuth provider");

    private static ApacheDsSSLContainer apacheDS;

    @AfterClass
    public static void afterClass() throws Exception {
        apacheDS.stop();
        Thread.sleep(1500);
    }

    @BeforeClass
    public static void startApacheDS() throws Exception {
        apacheDS = ApacheDSHelper.start(LDAP_PORT, LDAPS_PORT);
    }

    private final FieldDescriptor LDAP_TYPE = fieldWithPath("type").required().description("`ldap`");
    private final FieldDescriptor LDAP_ORIGIN_KEY = fieldWithPath("originKey").required().description("Origin key must be `ldap` for an LDAP provider");
    private final FieldDescriptor LDAP_PROFILE_FILE = fieldWithPath("config.ldapProfileFile").required().type(STRING).description("The file to be used for configuring the LDAP authentication. Options are: `ldap/ldap-simple-bind.xml`, `ldap/ldap-search-and-bind.xml`, `ldap/ldap-search-and-compare.xml`");
    private final FieldDescriptor LDAP_GROUP_FILE = fieldWithPath("config.ldapGroupFile").required().type(STRING).description("The file to be used for group integration. Options are: `ldap/ldap-groups-null.xml`, `ldap/ldap-groups-as-scopes.xml`, `ldap/ldap-groups-map-to-scopes.xml`");
    private final FieldDescriptor LDAP_URL = fieldWithPath("config.baseUrl").required().type(STRING).description("The URL to the ldap server, must start with `ldap://` or `ldaps://`");
    private final FieldDescriptor LDAP_BIND_USER_DN = fieldWithPath("config.bindUserDn").required().type(STRING).description("Used with `search-and-bind` and `search-and-compare`. A valid LDAP ID that has read permissions to perform a search of the LDAP tree for user information.");
    private final FieldDescriptor LDAP_BIND_PASSWORD = fieldWithPath("config.bindPassword").required().type(STRING).description("Used with `search-and-bind` and `search-and-compare`. Password for the LDAP ID that performs a search of the LDAP tree for user information.");
    private final FieldDescriptor LDAP_USER_SEARCH_BASE = fieldWithPath("config.userSearchBase").optional("dc=test,dc=com").type(STRING).description("Used with `search-and-bind` and `search-and-compare`. Define a base where the search starts at.");
    private final FieldDescriptor LDAP_USER_SEARCH_FILTER = fieldWithPath("config.userSearchFilter").optional("cn={0}").type(STRING).description("Used with `search-and-bind` and `search-and-compare`. Search filter used. Takes one parameter, user ID defined as `{0}`");
    private final FieldDescriptor LDAP_GROUP_SEARCH_BASE = fieldWithPath("config.groupSearchBase").required().type(STRING).description("Search start point for a user group membership search, use the value `memberOf` to skip group search, and use the memberOf attributes of the user.");
    private final FieldDescriptor LDAP_GROUP_SEARCH_FILTER = fieldWithPath("config.groupSearchFilter").required().type(STRING).description("Search query filter to find the groups a user belongs to, or for a nested search, groups that a group belongs to");
    private final FieldDescriptor LDAP_GROUP_AUTO_ADD = fieldWithPath("config.autoAddGroups").optional(true).type(BOOLEAN).description("Set to true when `profile_type=groups_as_scopes` to auto create scopes for a user. Ignored for other profiles.");
    private final FieldDescriptor LDAP_GROUP_SEARCH_SUBTREE = fieldWithPath("config.groupSearchSubTree").optional(true).type(BOOLEAN).description("Boolean value, set to true to search below the search base");
    private final FieldDescriptor LDAP_GROUP_MAX_SEARCH_DEPTH = fieldWithPath("config.maxGroupSearchDepth").optional(10).type(NUMBER).description("Set to number of levels a nested group search should go. Set to `1` to disable nested groups.");
    private final FieldDescriptor LDAP_USER_MAIL_ATTRIBUTE = fieldWithPath("config.mailAttributeName").optional(MAIL).type(STRING).description("The name of the LDAP attribute that contains the user's email address");
    private final FieldDescriptor LDAP_USER_MAIL_SUBSTITUTE = fieldWithPath("config.mailSubstitute").optional(null).type(STRING).description("Defines an email pattern containing a `{0}` to generate an email address for an LDAP user during authentication");
    private final FieldDescriptor LDAP_USER_MAIL_SUBSTITUTE_OVERRIDES_LDAP = fieldWithPath("config.mailSubstituteOverridesLdap").optional(false).type(BOOLEAN).description("Set to true if you wish to override an LDAP user email address with a generated one");
    private final FieldDescriptor LDAP_SSL_SKIP_VERIFICATION = fieldWithPath("config.skipSSLVerification").optional(false).type(BOOLEAN).description("Skips validation of the LDAP cert if set to true.");
    private final FieldDescriptor LDAP_SSL_TLS = fieldWithPath("config.tlsConfiguration").optional("none").type(STRING).description("Sets the StartTLS options, valid values are `none`, `simple` or `external`");
    private final FieldDescriptor LDAP_REFERRAL = fieldWithPath("config.referral").optional("follow").type(STRING).description("Configures the UAA LDAP referral behavior. The following values are possible:" +
                                                                                                                                   "  <ul><li>follow &rarr; Referrals are followed</li>" +
                                                                                                                                   "  <li>ignore &rarr; Referrals are ignored and the partial result is returned</li>" +
                                                                                                                                   "  <li>throw  &rarr; An error is thrown and the authentication is aborted</li></ul>" +
                                                                                                                                   "  Reference: [http://docs.oracle.com/javase/jndi/tutorial/ldap/referral/jndi.html](http://docs.oracle.com/javase/jndi/tutorial/ldap/referral/jndi.html)");
    private final FieldDescriptor LDAP_GROUPS_IGNORE_PARTIAL = fieldWithPath("config.groupsIgnorePartialResults").optional(null).type(BOOLEAN).description("Whether to ignore partial results errors from LDAP when mapping groups");
    private final FieldDescriptor LDAP_USER_DN_PATTERN = fieldWithPath("config.userDNPattern").optional("cn={0},ou=Users,dc=test,dc=com").type(STRING).description("Used with `simple-bind` only. A semi-colon separated lists of DN patterns to construct a DN direct from the user ID without performing a search.");
    private final FieldDescriptor LDAP_USER_DN_PATTERN_DELIM = fieldWithPath("config.userDNPatternDelimiter").optional(";").type(STRING).description("The delimiter character in between user DN patterns for `simple-bind` authentication.");

    private final FieldDescriptor LDAP_USER_COMPARE_PASSWORD_ATTRIBUTE_NAME = fieldWithPath("config.passwordAttributeName").optional("userPassword").type(STRING).description("Used with `search-and-compare` only. The name of the password attribute in the LDAP directory.");
    private final FieldDescriptor LDAP_USER_COMPARE_ENCODER = fieldWithPath("config.passwordEncoder").optional("org.cloudfoundry.identity.uaa.provider.ldap.DynamicPasswordComparator").type(STRING).description("Used with `search-and-compare` only. A fully-qualified Java classname to the password encoder. This encoder is used to properly encode user password to match the one in the LDAP directory.");
    private final FieldDescriptor LDAP_USER_COMPARE_LOCAL = fieldWithPath("config.localPasswordCompare").optional(null).type(BOOLEAN).description("Set to true if the comparison should be done locally. Setting this value to false implies that rather than retrieving the password, the UAA will run a query to match the password. In order for this query to work, you must know what type of hash/encoding/salt is used for the LDAP password.");
    private final FieldDescriptor LDAP_GROUP_ROLE_ATTRIBUTE = fieldWithPath("config.groupRoleAttribute").optional("description").type(STRING).description("Used with `groups-as-scopes`, defines the attribute that holds the scope name(s).");
    private final FieldDescriptor LDAP_ATTRIBUTE_MAPPING_FIRSTNAME = fieldWithPath("config.attributeMappings.first_name").optional("givenname").type(STRING).description(GIVEN_NAME_DESC);
    private final FieldDescriptor LDAP_ATTRIBUTE_MAPPING_LASTNAME = fieldWithPath("config.attributeMappings.family_name").optional("sn").type(STRING).description(FAMILY_NAME_DESC);
    private final FieldDescriptor LDAP_ATTRIBUTE_MAPPING_PHONE = fieldWithPath("config.attributeMappings.phone_number").optional("telephonenumber").type(STRING).description(PHONE_NUMBER_DESC);

    private FieldDescriptor[] ldapAllFields = (FieldDescriptor[]) ArrayUtils.addAll(commonProviderFields, new FieldDescriptor[]{
        LDAP_TYPE,
        LDAP_ORIGIN_KEY,
        LDAP_PROFILE_FILE,
        LDAP_GROUP_FILE,
        LDAP_URL,
        LDAP_BIND_USER_DN,
//        LDAP_BIND_PASSWORD,
        LDAP_USER_SEARCH_BASE,
        LDAP_USER_SEARCH_FILTER,
        LDAP_GROUP_SEARCH_BASE,
        LDAP_GROUP_SEARCH_FILTER,
        LDAP_GROUP_AUTO_ADD,
        LDAP_GROUP_SEARCH_SUBTREE,
        LDAP_GROUP_MAX_SEARCH_DEPTH,
        LDAP_USER_MAIL_ATTRIBUTE,
        LDAP_USER_MAIL_SUBSTITUTE,
        LDAP_USER_MAIL_SUBSTITUTE_OVERRIDES_LDAP,
        LDAP_SSL_SKIP_VERIFICATION,
        LDAP_SSL_TLS,
        LDAP_REFERRAL,
        LDAP_GROUPS_IGNORE_PARTIAL,
        LDAP_USER_DN_PATTERN,
        LDAP_USER_DN_PATTERN_DELIM,
        LDAP_USER_COMPARE_PASSWORD_ATTRIBUTE_NAME,
        LDAP_USER_COMPARE_ENCODER,
        LDAP_USER_COMPARE_LOCAL,
        LDAP_GROUP_ROLE_ATTRIBUTE,
        ATTRIBUTE_MAPPING,
        LDAP_ATTRIBUTE_MAPPING_FIRSTNAME,
        LDAP_ATTRIBUTE_MAPPING_LASTNAME,
        LDAP_ATTRIBUTE_MAPPING_PHONE,
        EXTERNAL_GROUPS_WHITELIST
    });


    private FieldDescriptor[] ldap_SearchAndCompare_GroupsAsScopes = (FieldDescriptor[]) ArrayUtils.addAll(commonProviderFields, new FieldDescriptor[]{
        LDAP_TYPE,
        LDAP_ORIGIN_KEY,
        LDAP_PROFILE_FILE,
        LDAP_GROUP_FILE,
        LDAP_URL,
        LDAP_BIND_USER_DN,
        LDAP_BIND_PASSWORD,
        LDAP_USER_SEARCH_BASE,
        LDAP_USER_SEARCH_FILTER,
        LDAP_GROUP_SEARCH_BASE,
        LDAP_GROUP_SEARCH_FILTER,
        LDAP_GROUP_AUTO_ADD,
        LDAP_GROUP_SEARCH_SUBTREE,
        LDAP_GROUP_MAX_SEARCH_DEPTH,
        LDAP_USER_MAIL_ATTRIBUTE,
        LDAP_USER_MAIL_SUBSTITUTE,
        LDAP_USER_MAIL_SUBSTITUTE_OVERRIDES_LDAP,
        LDAP_SSL_SKIP_VERIFICATION,
        LDAP_SSL_TLS,
        LDAP_REFERRAL,
        LDAP_GROUPS_IGNORE_PARTIAL,
        LDAP_USER_DN_PATTERN.ignored(),
        LDAP_USER_DN_PATTERN_DELIM.ignored(),
        LDAP_USER_COMPARE_PASSWORD_ATTRIBUTE_NAME,
        LDAP_USER_COMPARE_ENCODER,
        LDAP_USER_COMPARE_LOCAL,
        LDAP_GROUP_ROLE_ATTRIBUTE,
        ATTRIBUTE_MAPPING,
        LDAP_ATTRIBUTE_MAPPING_FIRSTNAME,
        LDAP_ATTRIBUTE_MAPPING_LASTNAME,
        LDAP_ATTRIBUTE_MAPPING_PHONE,
        EXTERNAL_GROUPS_WHITELIST
    });

    private FieldDescriptor[] ldapSimpleBindFields = (FieldDescriptor[]) ArrayUtils.addAll(commonProviderFields, new FieldDescriptor[]{
        LDAP_TYPE,
        LDAP_ORIGIN_KEY,
        LDAP_PROFILE_FILE,
        LDAP_GROUP_FILE,
        LDAP_URL,
        LDAP_USER_MAIL_ATTRIBUTE,
        LDAP_USER_MAIL_SUBSTITUTE,
        LDAP_USER_MAIL_SUBSTITUTE_OVERRIDES_LDAP,
        LDAP_SSL_SKIP_VERIFICATION,
        LDAP_SSL_TLS,
        LDAP_REFERRAL,
        LDAP_USER_DN_PATTERN,
        LDAP_USER_DN_PATTERN_DELIM,
        ATTRIBUTE_MAPPING,
        LDAP_ATTRIBUTE_MAPPING_FIRSTNAME,
        LDAP_ATTRIBUTE_MAPPING_LASTNAME,
        LDAP_ATTRIBUTE_MAPPING_PHONE,

        LDAP_BIND_USER_DN.ignored(),
        LDAP_USER_SEARCH_BASE.ignored(),
        LDAP_USER_SEARCH_FILTER.ignored(),
        LDAP_GROUP_SEARCH_BASE.ignored(),
        LDAP_GROUP_SEARCH_FILTER.ignored(),
        LDAP_GROUP_AUTO_ADD.ignored(),
        LDAP_GROUP_SEARCH_SUBTREE.ignored(),
        LDAP_GROUP_MAX_SEARCH_DEPTH.ignored(),
        LDAP_GROUPS_IGNORE_PARTIAL.ignored(),
        LDAP_USER_COMPARE_PASSWORD_ATTRIBUTE_NAME.ignored(),
        LDAP_USER_COMPARE_ENCODER.ignored(),
        LDAP_USER_COMPARE_LOCAL.ignored(),
        LDAP_GROUP_ROLE_ATTRIBUTE.ignored(),
        EXTERNAL_GROUPS_WHITELIST.ignored()
    });


    private FieldDescriptor[] ldapSearchAndBind_GroupsToScopes = (FieldDescriptor[]) ArrayUtils.addAll(commonProviderFields, new FieldDescriptor[]{
        LDAP_TYPE,
        LDAP_ORIGIN_KEY,
        LDAP_PROFILE_FILE,
        LDAP_GROUP_FILE,
        LDAP_URL,
        LDAP_BIND_USER_DN,
        LDAP_BIND_PASSWORD,
        LDAP_USER_SEARCH_BASE,
        LDAP_USER_SEARCH_FILTER,
        LDAP_GROUP_SEARCH_BASE,
        LDAP_GROUP_SEARCH_FILTER,
        LDAP_GROUP_AUTO_ADD.ignored(),
        LDAP_GROUP_SEARCH_SUBTREE,
        LDAP_GROUP_MAX_SEARCH_DEPTH,
        LDAP_USER_MAIL_ATTRIBUTE,
        LDAP_USER_MAIL_SUBSTITUTE,
        LDAP_USER_MAIL_SUBSTITUTE_OVERRIDES_LDAP,
        LDAP_SSL_SKIP_VERIFICATION,
        LDAP_SSL_TLS,
        LDAP_REFERRAL,
        LDAP_GROUPS_IGNORE_PARTIAL,
        LDAP_USER_DN_PATTERN.ignored(),
        LDAP_USER_DN_PATTERN_DELIM.ignored(),
        LDAP_USER_COMPARE_PASSWORD_ATTRIBUTE_NAME.ignored(),
        LDAP_USER_COMPARE_ENCODER.ignored(),
        LDAP_USER_COMPARE_LOCAL.ignored(),
        LDAP_GROUP_ROLE_ATTRIBUTE.ignored(),
        ATTRIBUTE_MAPPING,
        LDAP_ATTRIBUTE_MAPPING_FIRSTNAME,
        LDAP_ATTRIBUTE_MAPPING_LASTNAME,
        LDAP_ATTRIBUTE_MAPPING_PHONE,
        EXTERNAL_GROUPS_WHITELIST
    });

    @Before
    public void setUp() throws Exception {
        adminToken = testClient.getClientCredentialsOAuthAccessToken(
            "admin",
            "adminsecret",
            "");

        identityProviderProvisioning = getWebApplicationContext().getBean(JdbcIdentityProviderProvisioning.class);
    }

    @After
    public void clearUaaConfig() throws Exception {
        getWebApplicationContext().getBean(JdbcTemplate.class).update("UPDATE identity_provider SET config=null WHERE origin_key='uaa'");
    }

    @Test
    public void createSAMLIdentityProvider() throws Exception {
        IdentityProvider identityProvider = getSamlProvider("SAML");
        identityProvider.setSerializeConfigRaw(true);

        FieldDescriptor[] idempotentFields = (FieldDescriptor[]) ArrayUtils.addAll(commonProviderFields, new FieldDescriptor[]{
            fieldWithPath("type").required().description("`saml`"),
            fieldWithPath("originKey").required().description("A unique alias for the SAML provider"),
            SKIP_SSL_VALIDATION,
            STORE_CUSTOM_ATTRIBUTES,
            fieldWithPath("config.metaDataLocation").required().type(STRING).description("SAML Metadata - either an XML string or a URL that will deliver XML content"),
            fieldWithPath("config.nameID").optional(null).type(STRING).description("The name ID to use for the username, default is \"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified\"."),
            fieldWithPath("config.assertionConsumerIndex").optional(null).type(NUMBER).description("SAML assertion consumer index, default is 0"),
            fieldWithPath("config.metadataTrustCheck").optional(null).type(BOOLEAN).description("Should metadata be validated, defaults to false"),
            fieldWithPath("config.showSamlLink").optional(null).type(BOOLEAN).description("Should the SAML login link be displayed on the login page, defaults to false"),
            fieldWithPath("config.linkText").constrained("Required if the ``showSamlLink`` is set to true").type(STRING).description("The link text for the SAML IDP on the login page"),
            fieldWithPath("config.groupMappingMode").optional(EXPLICITLY_MAPPED).type(STRING).description("Either ``EXPLICITLY_MAPPED`` in order to map external groups to OAuth scopes using the group mappings, or ``AS_SCOPES`` to use SAML group names as scopes."),
            fieldWithPath("config.iconUrl").optional(null).type(STRING).description("Reserved for future use"),
            fieldWithPath("config.socketFactoryClassName").optional(null).description("Either `\"org.apache.commons.httpclient.protocol.DefaultProtocolSocketFactory\"` or" +
                "`\"org.apache.commons.httpclient.contrib.ssl.EasySSLProtocolSocketFactory\"` depending on if the `metaDataLocation` of type `URL` is HTTP or HTTPS, respectively"),
            ADD_SHADOW_USER_ON_LOGIN,
            EXTERNAL_GROUPS_WHITELIST,
            ATTRIBUTE_MAPPING,
            GIVEN_NAME,
            FAMILY_NAME,
            EMAIL,
            PHONE_NUMBER
        });

        Snippet requestFields = requestFields(idempotentFields);

        Snippet responseFields = responseFields((FieldDescriptor[]) ArrayUtils.addAll(idempotentFields, new FieldDescriptor[] {
            VERSION,
            ID,
            ADDITIONAL_CONFIGURATION,
            IDENTITY_ZONE_ID,
            CREATED,
            LAST_MODIFIED,
            fieldWithPath("config.idpEntityAlias").type(STRING).description("This will be set to ``originKey``"),
            fieldWithPath("config.zoneId").type(STRING).description("This will be set to the ID of the zone where the provider is being created")
        }));

        ResultActions resultActions = getMockMvc().perform(post("/identity-providers")
            .param("rawConfig", "true")
            .header("Authorization", "Bearer " + adminToken)
            .contentType(APPLICATION_JSON)
            .content(serializeExcludingProperties(identityProvider, "id", "version", "created", "last_modified", "identityZoneId", "config.zoneId", "config.idpEntityAlias", "config.additionalConfiguration")))
            .andExpect(status().isCreated());

        resultActions.andDo(document("{ClassName}/{methodName}",
            preprocessRequest(prettyPrint()),
            preprocessResponse(prettyPrint()),
            requestHeaders(
                headerWithName("Authorization").description("Bearer token containing `zones.<zone id>.admin` or `uaa.admin` or `idps.write` (only in the same zone that you are a user of)"),
                headerWithName("X-Identity-Zone-Id").description("May include this header to administer another zone if using `zones.<zone id>.admin` or `uaa.admin` scope against the default UAA zone.").optional()
            ),
            commonRequestParams,
            requestFields,
            responseFields
        ));
    }

    @Test
    public void createOAuthIdentityProvider() throws Exception {
        IdentityProvider identityProvider = new IdentityProvider();
        identityProvider.setType(OAUTH20);
        identityProvider.setName("UAA Provider");
        identityProvider.setOriginKey("my-oauth2-provider");
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
            fieldWithPath("type").required().description("`\""+OAUTH20+"\"`"),
            fieldWithPath("originKey").required().description("A unique alias for a OAuth provider"),
            fieldWithPath("config.authUrl").required().type(STRING).description("The OAuth 2.0 authorization endpoint URL"),
            fieldWithPath("config.tokenUrl").required().type(STRING).description("The OAuth 2.0 token endpoint URL"),
            fieldWithPath("config.tokenKeyUrl").optional(null).type(STRING).description("The URL of the token key endpoint which renders a verification key for validating token signatures"),
            fieldWithPath("config.tokenKey").optional(null).type(STRING).description("A verification key for validating token signatures, set to null if a `tokenKeyUrl` is provided."),
            fieldWithPath("config.showLinkText").optional(true).type(BOOLEAN).description("A flag controlling whether a link to this provider's login will be shown on the UAA login page"),
            fieldWithPath("config.linkText").optional(null).type(STRING).description("Text to use for the login link to the provider"),
            fieldWithPath("config.relyingPartyId").required().type(STRING).description("The client ID which is registered with the external OAuth provider for use by the UAA"),
            fieldWithPath("config.skipSslValidation").optional(null).type(BOOLEAN).description("A flag controlling whether SSL validation should be skipped when communicating with the external OAuth server"),
            fieldWithPath("config.scopes").optional(null).type(ARRAY).description("What scopes to request on a call to the external OAuth provider"),
            fieldWithPath("config.checkTokenUrl").optional(null).type(OBJECT).description("Reserved for future OAuth use."),
            fieldWithPath("config.responseType").optional("code").type(STRING).description("Response type for the authorize request, will be sent to OAuth server, defaults to `code`"),
            ADD_SHADOW_USER_ON_LOGIN,
            EXTERNAL_GROUPS,
            ATTRIBUTE_MAPPING,
            fieldWithPath("config.attributeMappings.user_name").optional("preferred_username").type(STRING).description("Map `user_name` to the attribute for username in the provider assertion."),
            fieldWithPath("config.issuer").optional(null).type(STRING).description("The OAuth 2.0 token issuer. This value is used to validate the issuer inside the token.")
        });
        Snippet requestFields = requestFields((FieldDescriptor[]) ArrayUtils.add(idempotentFields, relayingPartySecret));

        Snippet responseFields = responseFields((FieldDescriptor[]) ArrayUtils.addAll(idempotentFields, new FieldDescriptor[]{
            VERSION,
            ID,
            ADDITIONAL_CONFIGURATION,
            IDENTITY_ZONE_ID,
            CREATED,
            LAST_MODIFIED,
            fieldWithPath("config.externalGroupsWhitelist").optional(null).type(ARRAY).description("Not currently used.")
        }));

        ResultActions resultActions = getMockMvc().perform(post("/identity-providers")
            .param("rawConfig", "true")
            .header("Authorization", "Bearer " + adminToken)
            .contentType(APPLICATION_JSON)
            .content(serializeExcludingProperties(identityProvider, "id", "version", "created", "last_modified", "identityZoneId", "config.externalGroupsWhitelist", "config.checkTokenUrl", "config.additionalConfiguration")))
            .andExpect(status().isCreated());

        resultActions.andDo(document("{ClassName}/{methodName}",
            preprocessRequest(prettyPrint()),
            preprocessResponse(prettyPrint()),
            requestHeaders(
                headerWithName("Authorization").description("Bearer token containing `zones.<zone id>.admin` or `uaa.admin` or `idps.write` (only in the same zone that you are a user of)"),
                headerWithName("X-Identity-Zone-Id").description("May include this header to administer another zone if using `zones.<zone id>.admin` or `uaa.admin` scope against the default UAA zone.").optional()
            ),
            commonRequestParams,
            requestFields,
            responseFields
        ));
    }

    @Test
    public void createOidcIdentityProvider() throws Exception {
        IdentityProvider identityProvider = new IdentityProvider();
        identityProvider.setType(OIDC10);
        identityProvider.setName("UAA Provider");
        identityProvider.setOriginKey("my-oidc-provider-"+new RandomValueStringGenerator().generate().toLowerCase());
        OIDCIdentityProviderDefinition definition = new OIDCIdentityProviderDefinition();
        definition.setDiscoveryUrl(new URL("https://accounts.google.com/.well-known/openid-configuration"));
        definition.setSkipSslValidation(true);
        definition.setRelyingPartyId("uaa");
        definition.setRelyingPartySecret("secret");
        definition.setShowLinkText(false);
        identityProvider.setConfig(definition);
        identityProvider.setSerializeConfigRaw(true);

        FieldDescriptor[] idempotentFields = (FieldDescriptor[]) ArrayUtils.addAll(commonProviderFields, new FieldDescriptor[]{
            fieldWithPath("type").required().description("`\""+OIDC10+"\"`"),
            fieldWithPath("originKey").required().description("A unique alias for the OIDC 1.0 provider"),
            fieldWithPath("config.discoveryUrl").optional(null).type(STRING).description("The OpenID Connect Discovery URL, typically ends with /.well-known/openid-configurationmit "),
            fieldWithPath("config.authUrl").optional().type(STRING).description("The OIDC 1.0 authorization endpoint URL. This can be left blank if a discovery URL is provided. If both are provided, this property overrides the discovery URL.").attributes(new Attributes.Attribute("constraints", "Required unless `discoveryUrl` is set.")),
            fieldWithPath("config.tokenUrl").optional().type(STRING).description("The OIDC 1.0 token endpoint URL.  This can be left blank if a discovery URL is provided. If both are provided, this property overrides the discovery URL.").attributes(new Attributes.Attribute("constraints", "Required unless `discoveryUrl` is set.")),
            fieldWithPath("config.tokenKeyUrl").optional(null).type(STRING).description("The URL of the token key endpoint which renders a verification key for validating token signatures.  This can be left blank if a discovery URL is provided. If both are provided, this property overrides the discovery URL.").attributes(new Attributes.Attribute("constraints", "Required unless `discoveryUrl` is set.")),
            fieldWithPath("config.tokenKey").optional(null).type(STRING).description("A verification key for validating token signatures. We recommend not setting this as it will not allow for key rotation.  This can be left blank if a discovery URL is provided. If both are provided, this property overrides the discovery URL.").attributes(new Attributes.Attribute("constraints", "Required unless `discoveryUrl` is set.")),
            fieldWithPath("config.showLinkText").optional(true).type(BOOLEAN).description("A flag controlling whether a link to this provider's login will be shown on the UAA login page"),
            fieldWithPath("config.linkText").optional(null).type(STRING).description("Text to use for the login link to the provider"),
            fieldWithPath("config.relyingPartyId").required().type(STRING).description("The client ID which is registered with the external OAuth provider for use by the UAA"),
            fieldWithPath("config.skipSslValidation").optional(null).type(BOOLEAN).description("A flag controlling whether SSL validation should be skipped when communicating with the external OAuth server"),
            fieldWithPath("config.scopes").optional(null).type(ARRAY).description("What scopes to request on a call to the external OAuth/OpenID provider. For example, can provide " +
                                                                                      "`openid`, `roles`, or `profile` to request ID token, scopes populated in the ID token external groups attribute mappings, or the user profile information, respectively."),
            fieldWithPath("config.checkTokenUrl").optional(null).type(OBJECT).description("Reserved for future OAuth/OIDC use."),
            fieldWithPath("config.userInfoUrl").optional(null).type(OBJECT).description("Reserved for future OIDC use.  This can be left blank if a discovery URL is provided. If both are provided, this property overrides the discovery URL."),
            fieldWithPath("config.responseType").optional("code").type(STRING).description("Response type for the authorize request, defaults to `code`, but can be `code id_token` if the OIDC server can return an id_token as a query parameter in the redirect."),
            ADD_SHADOW_USER_ON_LOGIN,
            EXTERNAL_GROUPS,
            ATTRIBUTE_MAPPING,
            fieldWithPath("config.attributeMappings.user_name").optional("preferred_username").type(STRING).description("Map `user_name` to the attribute for username in the provider assertion."),
            fieldWithPath("config.issuer").optional(null).type(STRING).description("The OAuth 2.0 token issuer. This value is used to validate the issuer inside the token.")
        });
        Snippet requestFields = requestFields((FieldDescriptor[]) ArrayUtils.add(idempotentFields, relayingPartySecret));

        Snippet responseFields = responseFields((FieldDescriptor[]) ArrayUtils.addAll(idempotentFields, new FieldDescriptor[]{
            VERSION,
            ID,
            ADDITIONAL_CONFIGURATION,
            IDENTITY_ZONE_ID,
            CREATED,
            LAST_MODIFIED,
            fieldWithPath("config.externalGroupsWhitelist").optional(null).type(ARRAY).description("Not currently used.")
        }));

        ResultActions resultActions = getMockMvc().perform(post("/identity-providers")
                                                               .param("rawConfig", "true")
                                                               .header("Authorization", "Bearer " + adminToken)
                                                               .contentType(APPLICATION_JSON)
                                                               .content(serializeExcludingProperties(identityProvider, "id", "version", "created", "last_modified", "identityZoneId", "config.externalGroupsWhitelist", "config.checkTokenUrl", "config.additionalConfiguration")))
            .andDo(print())
            .andExpect(status().isCreated());

        resultActions.andDo(document("{ClassName}/{methodName}",
                                     preprocessRequest(prettyPrint()),
                                     preprocessResponse(prettyPrint()),
                                     requestHeaders(
                                         headerWithName("Authorization").description("Bearer token containing `zones.<zone id>.admin` or `uaa.admin` or `idps.write` (only in the same zone that you are a user of)"),
                                         headerWithName("X-Identity-Zone-Id").description("May include this header to administer another zone if using `zones.<zone id>.admin` or `uaa.admin` scope against the default UAA zone.").optional()
                                     ),
                                     commonRequestParams,
                                     requestFields,
                                     responseFields
        ));
    }

    @Test
    public void create_Simple_Bind_LDAPIdentityProvider() throws Exception {
        IdentityProvider identityProvider = MultitenancyFixture.identityProvider(OriginKeys.LDAP, "");
        identityProvider.setType(LDAP);


        LdapIdentityProviderDefinition providerDefinition = new LdapIdentityProviderDefinition();
        providerDefinition.setLdapProfileFile("ldap/ldap-simple-bind.xml");
        providerDefinition.setLdapGroupFile("ldap/ldap-groups-null.xml");
        providerDefinition.setBaseUrl(ldapServerUrl);
        providerDefinition.setUserDNPattern("cn={0},ou=Users,dc=test,dc=com");
        providerDefinition.setUserDNPatternDelimiter(";");
        providerDefinition.setMailAttributeName("mail");
        identityProvider.setConfig(providerDefinition);
        providerDefinition.setBindPassword(null);
        identityProvider.setSerializeConfigRaw(true);

        FieldDescriptor[] fields = ldapSimpleBindFields;
        createLDAPProvider(identityProvider, fields, "create_Simple_Bind_LDAPIdentityProvider");
    }

    @Test
    public void create_SearchAndBind_Groups_Map_ToScopes_LDAPIdentityProvider() throws Exception {
        IdentityProvider identityProvider = MultitenancyFixture.identityProvider(OriginKeys.LDAP, "");
        identityProvider.setType(LDAP);

        LdapIdentityProviderDefinition providerDefinition = new LdapIdentityProviderDefinition();
        providerDefinition.setLdapProfileFile("ldap/ldap-search-and-bind.xml");
        providerDefinition.setLdapGroupFile("ldap/ldap-groups-map-to-scopes.xml");
        providerDefinition.setBaseUrl(ldapServerUrl);
        providerDefinition.setBindUserDn("cn=admin,ou=Users,dc=test,dc=com");
        providerDefinition.setBindPassword("adminsecret");
        providerDefinition.setUserSearchBase("dc=test,dc=com");
        providerDefinition.setUserSearchFilter("cn={0}");
        providerDefinition.setGroupSearchBase("ou=scopes,dc=test,dc=com");
        providerDefinition.setGroupSearchFilter("member={0}");
        providerDefinition.setMailAttributeName("mail");
        providerDefinition.setMailSubstitute("{0}@my.org");
        providerDefinition.setMailSubstituteOverridesLdap(false);
        providerDefinition.setGroupSearchSubTree(true);
        providerDefinition.setMaxGroupSearchDepth(3);

        identityProvider.setConfig(providerDefinition);
        identityProvider.setSerializeConfigRaw(true);

        FieldDescriptor[] fields = (FieldDescriptor[]) ArrayUtils.add(ldapSearchAndBind_GroupsToScopes, LDAP_BIND_PASSWORD);
        createLDAPProvider(identityProvider, fields, "create_SearchAndBind_Groups_Map_ToScopes_LDAPIdentityProvider");

    }

    @Test
    public void create_SearchAndCompare_Groups_As_Scopes_LDAPIdentityProvider() throws Exception {
        IdentityProvider identityProvider = MultitenancyFixture.identityProvider(OriginKeys.LDAP, "");
        identityProvider.setType(LDAP);

        LdapIdentityProviderDefinition providerDefinition = new LdapIdentityProviderDefinition();
        providerDefinition.setLdapProfileFile("ldap/ldap-search-and-compare.xml");
        providerDefinition.setLdapGroupFile("ldap/ldap-groups-as-scopes.xml");
        providerDefinition.setBaseUrl(ldapServerUrl);
        providerDefinition.setBindUserDn("cn=admin,ou=Users,dc=test,dc=com");
        providerDefinition.setBindPassword("adminsecret");
        providerDefinition.setUserSearchBase("dc=test,dc=com");
        providerDefinition.setUserSearchFilter("cn={0}");
        providerDefinition.setPasswordAttributeName("userPassword");
        providerDefinition.setLocalPasswordCompare(true);
        providerDefinition.setPasswordEncoder(DynamicPasswordComparator.class.getName());

        providerDefinition.setGroupSearchBase("ou=scopes,dc=test,dc=com");
        providerDefinition.setGroupSearchFilter("member={0}");
        providerDefinition.setAutoAddGroups(true);
        providerDefinition.setGroupSearchSubTree(true);
        providerDefinition.setMaxGroupSearchDepth(3);
        providerDefinition.setGroupRoleAttribute("description");

        identityProvider.setConfig(providerDefinition);
        identityProvider.setSerializeConfigRaw(true);

        FieldDescriptor[] fields = ldap_SearchAndCompare_GroupsAsScopes;
        createLDAPProvider(identityProvider, fields, "create_SearchAndCompare_Groups_As_Scopes_LDAPIdentityProvider");

    }

    public void createLDAPProvider(IdentityProvider<LdapIdentityProviderDefinition> identityProvider,
                                   FieldDescriptor[] fields,
                                   String name) throws Exception {
        BaseClientDetails admin = new BaseClientDetails(
            "admin",
            null,
            "",
            "client_credentials",
            "uaa.admin",
             "http://redirect.url"
        );
        admin.setClientSecret("adminsecret");

        IdentityZoneCreationResult zone =
            MockMvcUtils.createOtherIdentityZoneAndReturnResult(new RandomValueStringGenerator(8).generate().toLowerCase(),
                                                                getMockMvc(),
                                                                getWebApplicationContext(),
                                                                admin);


        Snippet requestFields = requestFields(fields);

        Snippet responseFields = responseFields((FieldDescriptor[]) ArrayUtils.addAll(ldapAllFields, new FieldDescriptor[]{
            VERSION,
            ID,
            ADDITIONAL_CONFIGURATION,
            IDENTITY_ZONE_ID,
            CREATED,
            LAST_MODIFIED
        }));

        ResultActions resultActions = getMockMvc().perform(post("/identity-providers")
            .header(IdentityZoneSwitchingFilter.SUBDOMAIN_HEADER, zone.getIdentityZone().getSubdomain())
            .param("rawConfig", "true")
            .header("Authorization", "Bearer " + zone.getZoneAdminToken())
            .contentType(APPLICATION_JSON)
            .content(serializeExcludingProperties(identityProvider, "id", "version", "created", "last_modified", "identityZoneId", "config.additionalConfiguration")))
            .andExpect(status().isCreated());

        resultActions.andDo(document("{ClassName}/"+name,
                                     preprocessRequest(prettyPrint()),
                                     preprocessResponse(prettyPrint()),
                                     requestHeaders(
                                         headerWithName("Authorization").description("Bearer token containing `zones.<zone id>.admin` or `uaa.admin` or `idps.write` (only in the same zone that you are a user of)"),
                                         headerWithName("X-Identity-Zone-Id").description("May include this header to administer another zone if using `zones.<zone id>.admin` or `uaa.admin` scope against the default UAA zone.").optional()
                                     ),
                                     commonRequestParams,
                                     requestFields,
                                     responseFields
        ));

        getMockMvc().perform(
            post("/login.do")
                .header("Host", zone.getIdentityZone().getSubdomain()+".localhost")
                .with(cookieCsrf())
                .param("username", "marissa4")
                .param("password", "ldap4")
        )
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("/"));

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
            .param("rawConfig", "false")
            .header("Authorization", "Bearer " + adminToken)
            .contentType(APPLICATION_JSON))
            .andExpect(status().isOk())
            .andDo(document("{ClassName}/{methodName}",
                preprocessResponse(prettyPrint()),
                requestHeaders(
                    headerWithName("Authorization").description("Bearer token containing `zones.<zone id>.admin` or `zones.<zone id>.idps.read` or `uaa.admin` or `idps.read` (only in the same zone that you are a user of)"),
                    headerWithName("X-Identity-Zone-Id").description("May include this header to administer another zone if using `zones.<zone id>.admin` or `zones.<zone id>.idps.read` or `uaa.admin` scope against the default UAA zone.").optional()
                ),
                commonRequestParams,
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
            .param("rawConfig", "false")
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
                commonRequestParams,
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
            fieldWithPath("config.passwordPolicy").ignored(),
            fieldWithPath("config.passwordPolicy.minLength").constrained("Required when `passwordPolicy` in the config is not null").type(NUMBER).description("Minimum number of characters required for password to be considered valid (defaults to 0).").optional(),
            fieldWithPath("config.passwordPolicy.maxLength").constrained("Required when `passwordPolicy` in the config is not null").type(NUMBER).description("Maximum number of characters required for password to be considered valid (defaults to 255).").optional(),
            fieldWithPath("config.passwordPolicy.requireUpperCaseCharacter").constrained("Required when `passwordPolicy` in the config is not null").type(NUMBER).description("Minimum number of uppercase characters required for password to be considered valid (defaults to 0).").optional(),
            fieldWithPath("config.passwordPolicy.requireLowerCaseCharacter").constrained("Required when `passwordPolicy` in the config is not null").type(NUMBER).description("Minimum number of lowercase characters required for password to be considered valid (defaults to 0).").optional(),
            fieldWithPath("config.passwordPolicy.requireDigit").constrained("Required when `passwordPolicy` in the config is not null").type(NUMBER).description("Minimum number of digits required for password to be considered valid (defaults to 0).").optional(),
            fieldWithPath("config.passwordPolicy.requireSpecialCharacter").constrained("Required when `passwordPolicy` in the config is not null").type(NUMBER).description("Minimum number of special characters required for password to be considered valid (defaults to 0).").optional(),
            fieldWithPath("config.passwordPolicy.expirePasswordInMonths").constrained("Required when `passwordPolicy` in the config is not null").type(NUMBER).description("Number of months after which current password expires (defaults to 0).").optional(),
            fieldWithPath("config.passwordPolicy.passwordNewerThan").constrained("Required when `passwordPolicy` in the config is not null").type(NUMBER).description("This timestamp value can be used to force change password for every user. If the user's passwordLastModified is older than this value, the password is expired (defaults to null)."),
            fieldWithPath("config.lockoutPolicy.lockoutPeriodSeconds").constrained("Required when `LockoutPolicy` in the config is not null").type(NUMBER).description("Number of seconds in which lockoutAfterFailures failures must occur in order for account to be locked (defaults to 3600).").optional(),
            fieldWithPath("config.lockoutPolicy.lockoutAfterFailures").constrained("Required when `LockoutPolicy` in the config is not null").type(NUMBER).description("Number of allowed failures before account is locked (defaults to 5).").optional(),
            fieldWithPath("config.lockoutPolicy.countFailuresWithin").constrained("Required when `LockoutPolicy` in the config is not null").type(NUMBER).description("Number of seconds to lock out an account when lockoutAfterFailures failures is exceeded (defaults to 300).").optional(),
            fieldWithPath("config.disableInternalUserManagement").optional(null).type(BOOLEAN).description("When set to true, user management is disabled for this provider, defaults to false").optional()
        });
        Snippet requestFields = requestFields(idempotentFields);

        Snippet responseFields = responseFields((FieldDescriptor[]) ArrayUtils.addAll(idempotentFields, new FieldDescriptor[]{
            VERSION,
            ID,
            ADDITIONAL_CONFIGURATION,
            IDENTITY_ZONE_ID,
            CREATED,
            LAST_MODIFIED,
        }));

        getMockMvc().perform(put("/identity-providers/{id}", identityProvider.getId())
            .param("rawConfig", "true")
            .header("Authorization", "Bearer " + adminToken)
            .contentType(APPLICATION_JSON)
            .content(serializeExcludingProperties(identityProvider, "id", "created", "last_modified", "identityZoneId", "config.additionalConfiguration")))
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
                commonRequestParams,
                requestFields,
                responseFields));
    }

    @Test
    public void patchIdentityProviderStatus() throws Exception {
        IdentityProvider identityProvider = identityProviderProvisioning.retrieveByOrigin(OriginKeys.UAA, IdentityZoneHolder.get().getId());
        identityProvider.setConfig(new UaaIdentityProviderDefinition(new PasswordPolicy(0, 20, 0, 0, 0, 0, 0), null));
        identityProviderProvisioning.update(identityProvider);
        IdentityProviderStatus identityProviderStatus = new IdentityProviderStatus();
        identityProviderStatus.setRequirePasswordChange(true);

        FieldDescriptor[] idempotentFields = new FieldDescriptor[]{
            fieldWithPath("requirePasswordChange").required().description("Set to `true` in order to force password change for all users. The `passwordNewerThan` property in PasswordPolicy of the IdentityProvider will be updated with current system time. If the user's passwordLastModified is older than this value, the password is expired.")
        };

        Snippet requestFields = requestFields(idempotentFields);
        Snippet responseFields = responseFields(idempotentFields);

        getMockMvc().perform(patch("/identity-providers/{id}/status", identityProvider.getId())
                    .header("Authorization", "Bearer " + adminToken)
                    .contentType(APPLICATION_JSON)
                    .content(serializeExcludingProperties(identityProviderStatus)))
                .andExpect(status().isOk())
                .andDo(document("{ClassName}/{methodName}",
                        preprocessResponse(prettyPrint()),
                        pathParameters(parameterWithName("id").description(ID_DESC)
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
                commonRequestParams,
                responseFields(getCommonProviderFieldsAnyType())));
    }

    private ResultActions deleteIdentityProviderHelper(String id) throws Exception {
        return getMockMvc().perform(delete("/identity-providers/{id}", id)
            .param("rawConfig", "false")
            .header("Authorization", "Bearer " + adminToken)
            .contentType(APPLICATION_JSON))
            .andExpect(status().isOk());
    }

    private FieldDescriptor[] getCommonProviderFieldsAnyType() {
        return (FieldDescriptor[]) ArrayUtils.addAll(commonProviderFields, new FieldDescriptor[]{
            fieldWithPath("type").required().description("Type of the identity provider."),
            fieldWithPath("originKey").required().description("Unique identifier for the identity provider."),
            CONFIG,
            ADDITIONAL_CONFIGURATION,
            VERSION,
            ID,
            IDENTITY_ZONE_ID,
            CREATED,
            LAST_MODIFIED
        });
    }



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
