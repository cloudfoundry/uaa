/*
 * *****************************************************************************
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

import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LDAP;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OAUTH20;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OIDC10;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.SAML;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.CookieCsrfPostProcessor.cookieCsrf;
import static org.cloudfoundry.identity.uaa.provider.IdentityProvider.FIELD_ALIAS_ID;
import static org.cloudfoundry.identity.uaa.provider.IdentityProvider.FIELD_ALIAS_ZID;
import static org.cloudfoundry.identity.uaa.provider.IdentityProvider.FIELD_IDENTITY_ZONE_ID;
import static org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition.MAIL;
import static org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition.EMAIL_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition.EMAIL_VERIFIED_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition.ExternalGroupMappingMode;
import static org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition.FAMILY_NAME_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition.GIVEN_NAME_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition.GROUP_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition.PHONE_NUMBER_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition.USER_ATTRIBUTE_PREFIX;
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
import static org.springframework.restdocs.request.RequestDocumentation.queryParameters;
import static org.springframework.restdocs.snippet.Attributes.key;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.net.URI;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.collections4.map.HashedMap;
import org.apache.commons.lang3.ArrayUtils;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.login.Prompt;
import org.cloudfoundry.identity.uaa.mock.EndpointDocs;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.IdentityZoneCreationResult;
import org.cloudfoundry.identity.uaa.provider.AbstractExternalOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderStatus;
import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.LockoutPolicy;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.PasswordPolicy;
import org.cloudfoundry.identity.uaa.provider.RawExternalOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.ldap.DynamicPasswordComparator;
import org.cloudfoundry.identity.uaa.provider.saml.BootstrapSamlIdentityProviderDataTests;
import org.cloudfoundry.identity.uaa.test.InMemoryLdapServer;
import org.cloudfoundry.identity.uaa.test.SnippetUtils;
import org.cloudfoundry.identity.uaa.util.AlphanumericRandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.restdocs.headers.HeaderDescriptor;
import org.springframework.restdocs.payload.FieldDescriptor;
import org.springframework.restdocs.snippet.Attributes;
import org.springframework.restdocs.snippet.Snippet;
import org.springframework.test.web.servlet.ResultActions;

class IdentityProviderEndpointDocs extends EndpointDocs {

    private static final String NAME_DESC = "Human-readable name for this provider";
    private static final String VERSION_DESC = "Version of the identity provider data. Clients can use this to protect against conflicting updates";
    private static final String ACTIVE_DESC = "Defaults to true.";
    private static final String ID_DESC = "Unique identifier for this provider - GUID generated by the UAA";
    private static final String IDENTITY_ZONE_ID_DESC = "Set to the zone that this provider will be active in. Determined either by the Host header or the zone switch header.";
    private static final String CREATED_DESC = "UAA sets the creation date";
    private static final String LAST_MODIFIED_DESC = "UAA sets the modification date";
    private static final String CONFIG_DESCRIPTION = "Json config for the Identity Provider";
    private static final String FAMILY_NAME_DESC = "Map `family_name` to the attribute for family name in the provider assertion or token.";
    private static final String PHONE_NUMBER_DESC = "Map `phone_number` to the attribute for phone number in the provider assertion or token.";
    private static final String GIVEN_NAME_DESC = "Map `given_name` to the attribute for given name in the provider assertion or token.";
    private static final String ALIAS_ID_DESC = "The ID of the alias IdP.";
    private static final String ALIAS_ZID_DESC = "The ID of the identity zone in which an alias of this IdP is maintained.";
    private static final String ALIAS_ZID_DESC_CREATE = ALIAS_ZID_DESC +
            " Defaults to `null`. " +
            "Only supported for identity providers of type \"" + SAML + "\", \"" + OIDC10 + "\" and \"" + OAUTH20 + "\". " +
            "If set, the field must reference an existing identity zone that is different to the one referenced in `" + FIELD_IDENTITY_ZONE_ID + "`. " +
            "Alias identity providers can only be created from or to the \"uaa\" identity zone, i.e., one of `" + FIELD_IDENTITY_ZONE_ID + "` or `" + FIELD_ALIAS_ZID + "` must be set to \"uaa\".";
    private static final FieldDescriptor STORE_CUSTOM_ATTRIBUTES = fieldWithPath("config.storeCustomAttributes").optional(true).type(BOOLEAN).description("Set to true, to store custom user attributes to be fetched from the /userinfo endpoint");
    private static final FieldDescriptor SKIP_SSL_VALIDATION = fieldWithPath("config.skipSslValidation").optional(false).type(BOOLEAN).description("Set to true, to skip SSL validation when fetching metadata.");
    private static final FieldDescriptor ATTRIBUTE_MAPPING = fieldWithPath("config.attributeMappings").optional(null).type(OBJECT).description("Map external attribute to UAA recognized mappings.");
    private static final FieldDescriptor ATTRIBUTE_MAPPING_EMAIL = fieldWithPath("config.attributeMappings.email").optional(null).type(STRING).description("Map `email` to the attribute for email in the provider assertion or token.");
    private static final FieldDescriptor ATTRIBUTE_MAPPING_GIVEN_NAME = fieldWithPath("config.attributeMappings.given_name").optional(null).type(STRING).description(GIVEN_NAME_DESC);
    private static final FieldDescriptor ATTRIBUTE_MAPPING_FAMILY_NAME = fieldWithPath("config.attributeMappings.family_name").optional(null).type(STRING).description(FAMILY_NAME_DESC);
    private static final FieldDescriptor ATTRIBUTE_MAPPING_PHONE = fieldWithPath("config.attributeMappings.phone_number").optional(null).type(STRING).description(PHONE_NUMBER_DESC);
    private static final FieldDescriptor ATTRIBUTE_MAPPING_EMAIL_VERIFIED_FIELD = fieldWithPath("config.attributeMappings.email_verified").optional(null).type(STRING).description("Maps the attribute on the assertion to the `email_verified` user record at the time of authentication. Default is false. Once set to true, record remains true for subsequent authentications.");
    private static final FieldDescriptor ATTRIBUTE_MAPPING_EXTERNAL_GROUP = fieldWithPath("config.attributeMappings.external_groups").optional(null).type(ARRAY).description("Map `external_groups` to the attribute for groups in the provider assertion.");
    private static final FieldDescriptor ATTRIBUTE_MAPPING_CUSTOM_ATTRIBUTES_DEPARTMENT = fieldWithPath("config.attributeMappings['user.attribute.department']").optional(null).type(STRING).description("Map external attribute to UAA recognized mappings. Mapping should be of the format `user.attribute.<attribute_name>`. `department` is used in the documentation as an example attribute.");
    private static final FieldDescriptor ADD_SHADOW_USER = fieldWithPath("config.addShadowUserOnLogin").optional(true).type(BOOLEAN).description(" Determines whether users should be allowed to authenticate without having a user pre-populated in the users database (if true), or whether shadow users must be created before login by an administrator (if false).");
    private static final FieldDescriptor EXTERNAL_GROUPS_WHITELIST = fieldWithPath("config.externalGroupsWhitelist").optional(null).type(ARRAY).description("List of external groups that will be included in the ID Token if the `roles` scope is requested.");
    private static final FieldDescriptor PROVIDER_DESC = fieldWithPath("config.providerDescription").optional(null).type(STRING).description("Human readable name/description of this provider");
    private static final FieldDescriptor EMAIL_DOMAIN = fieldWithPath("config.emailDomain").optional(null).type(ARRAY).description("List of email domains associated with the provider for the purpose of associating users to the correct origin upon invitation. If empty list, no invitations are accepted. Wildcards supported.");
    private static final FieldDescriptor ACTIVE = fieldWithPath("active").optional(null).description(ACTIVE_DESC);
    private static final FieldDescriptor NAME = fieldWithPath("name").required().description(NAME_DESC);
    private static final FieldDescriptor CONFIG = fieldWithPath("config").required().description("Various configuration properties for the identity provider.");
    private static final FieldDescriptor ID = fieldWithPath("id").type(STRING).description(ID_DESC);
    private static final FieldDescriptor CREATED = fieldWithPath("created").description(CREATED_DESC);
    private static final FieldDescriptor LAST_MODIFIED = fieldWithPath("last_modified").description(LAST_MODIFIED_DESC);
    private static final FieldDescriptor GROUP_WHITELIST = fieldWithPath("config.externalGroupsWhitelist").optional(null).type(ARRAY).description("JSON Array containing the groups names which need to be populated in the user's `id_token` or response from `/userinfo` endpoint. If you don't specify the whitelist no groups will be populated in the `id_token` or `/userinfo` response." +
            "<br>Please note that regex is allowed. Acceptable patterns are" +
            "<ul><li>    `*` translates to all groups </li>" +
            "<li>         `*pattern*` Contains pattern </li>" +
            "<li>         `pattern*` Starts with pattern </li>" +
            "<li>         `*pattern` Ends with pattern </li></ul>");
    private static final FieldDescriptor IDENTITY_ZONE_ID = fieldWithPath(FIELD_IDENTITY_ZONE_ID).type(STRING).description(IDENTITY_ZONE_ID_DESC);
    private static final FieldDescriptor ADDITIONAL_CONFIGURATION = fieldWithPath("config.additionalConfiguration").optional(null).type(OBJECT).description("(Unused.)");
    private static final SnippetUtils.ConstrainableField VERSION = (SnippetUtils.ConstrainableField) fieldWithPath("version").type(NUMBER).description(VERSION_DESC);
    private static final Snippet commonRequestParams = queryParameters(parameterWithName("rawConfig").optional("false").type(BOOLEAN).description("<small><mark>UAA 3.4.0</mark></small> Flag indicating whether the response should use raw, unescaped JSON for the `config` field of the IDP, rather than the default behavior of encoding the JSON as a string."));

    private String adminToken;
    private IdentityProviderProvisioning identityProviderProvisioning;

    private final FieldDescriptor[] commonProviderFields = {
            NAME,
            PROVIDER_DESC,
            EMAIL_DOMAIN,
            ACTIVE,
            ADD_SHADOW_USER,
            STORE_CUSTOM_ATTRIBUTES
    };

    private static final FieldDescriptor[] ALIAS_FIELDS_GET = {
            fieldWithPath(FIELD_ALIAS_ID)
                    .attributes(key("constraints").value("Optional"))
                    .optional().type(STRING)
                    .description(ALIAS_ID_DESC),
            fieldWithPath(FIELD_ALIAS_ZID)
                    .attributes(key("constraints").value("Optional"))
                    .optional().type(STRING)
                    .description(ALIAS_ZID_DESC)
    };

    private static final FieldDescriptor[] ALIAS_FIELDS_CREATE = {
            fieldWithPath(FIELD_ALIAS_ID)
                    .attributes(key("constraints").value("Optional"))
                    .optional().type(STRING)
                    .description(ALIAS_ID_DESC + " Must be set to `null`."),
            fieldWithPath(FIELD_ALIAS_ZID)
                    .attributes(key("constraints").value("Optional"))
                    .optional().type(STRING)
                    .description(ALIAS_ZID_DESC_CREATE + " If set, an alias identity provider is created in the referenced zone and `" + FIELD_ALIAS_ID + "` is set accordingly.")
    };

    private static final FieldDescriptor[] ALIAS_FIELDS_LDAP_CREATE = {
            fieldWithPath(FIELD_ALIAS_ID)
                    .attributes(key("constraints").value("Optional"))
                    .optional().type(STRING)
                    .description(ALIAS_ID_DESC + " Must be set to `null`, since alias identity providers are not supported for LDAP."),
            fieldWithPath(FIELD_ALIAS_ZID)
                    .attributes(key("constraints").value("Optional"))
                    .optional().type(STRING)
                    .description(ALIAS_ZID_DESC + " Must be set to `null`, since alias identity providers are not supported for LDAP.")
    };

    private static final FieldDescriptor[] ALIAS_FIELDS_UPDATE = {
            fieldWithPath(FIELD_ALIAS_ID)
                    .attributes(key("constraints").value("Optional"))
                    .optional().type(STRING)
                    .description(ALIAS_ID_DESC + " The `" + FIELD_ALIAS_ID + "` value of the existing identity provider must be left unchanged."),
            fieldWithPath(FIELD_ALIAS_ZID)
                    .attributes(key("constraints").value("Optional"))
                    .optional().type(STRING)
                    .description(ALIAS_ZID_DESC_CREATE + " If set and the identity provider did not reference an alias before, an alias identity provider is created in the referenced zone and `" + FIELD_ALIAS_ID + "` is set accordingly. " +
                            "If the identity provider already referenced an alias identity provider before the update, this field must be left unchanged.")
    };

    private final FieldDescriptor[] attributeMappingFields = {
            ATTRIBUTE_MAPPING,
            ATTRIBUTE_MAPPING_EMAIL,
            ATTRIBUTE_MAPPING_GIVEN_NAME,
            ATTRIBUTE_MAPPING_FAMILY_NAME,
            ATTRIBUTE_MAPPING_PHONE,
            ATTRIBUTE_MAPPING_EMAIL_VERIFIED_FIELD,
            ATTRIBUTE_MAPPING_EXTERNAL_GROUP,
            ATTRIBUTE_MAPPING_CUSTOM_ATTRIBUTES_DEPARTMENT
    };

    private final FieldDescriptor relyingPartySecret = fieldWithPath("config.relyingPartySecret").constrained("Required if `config.authMethod` is set to `client_secret_basic`.").type(STRING).description("The client secret of the relying party at the external OAuth provider. If not set and `jwtClientAuthentication` is not set, then the external OAuth client is treated as public client and the flow is protected with [PKCE](https://tools.ietf.org/html/rfc7636) using code challenge method `S256`. It is recommended to set `jwtClientAuthentication:true` instead.");

    private static InMemoryLdapServer ldapContainer;

    @AfterAll
    static void afterClass() throws Exception {
        ldapContainer.stop();
        Thread.sleep(1500);
    }

    @BeforeAll
    static void startLdapContainer() {
        ldapContainer = InMemoryLdapServer.startLdap();
    }

    private final FieldDescriptor ldapType = fieldWithPath("type").required().description("`ldap`");
    private final FieldDescriptor ldapOriginKey = fieldWithPath("originKey").required().description("Origin key must be `ldap` for an LDAP provider");
    private final FieldDescriptor ldapProfileFile = fieldWithPath("config.ldapProfileFile").required().type(STRING).description("The file to be used for configuring the LDAP authentication. Options are: `ldap/ldap-simple-bind.xml`, `ldap/ldap-search-and-bind.xml`, `ldap/ldap-search-and-compare.xml`");
    private final FieldDescriptor ldapGroupFile = fieldWithPath("config.ldapGroupFile").required().type(STRING).description("The file to be used for group integration. Options are: `ldap/ldap-groups-null.xml`, `ldap/ldap-groups-as-scopes.xml`, `ldap/ldap-groups-map-to-scopes.xml`");
    private final FieldDescriptor ldapUrl = fieldWithPath("config.baseUrl").required().type(STRING).description("The URL to the ldap server, must start with `ldap://` or `ldaps://`");
    private final FieldDescriptor ldapBindUserDn = fieldWithPath("config.bindUserDn").required().type(STRING).description("Used with `search-and-bind` and `search-and-compare`. A valid LDAP ID that has read permissions to perform a search of the LDAP tree for user information.");
    private final FieldDescriptor ldapBindPassword = fieldWithPath("config.bindPassword").required().type(STRING).description("Used with `search-and-bind` and `search-and-compare`. Password for the LDAP ID that performs a search of the LDAP tree for user information.");
    private final FieldDescriptor ldapUserSearchBase = fieldWithPath("config.userSearchBase").optional("dc=test,dc=com").type(STRING).description("Used with `search-and-bind` and `search-and-compare`. Define a base where the search starts at.");
    private final FieldDescriptor ldapUserSearchFilter = fieldWithPath("config.userSearchFilter").optional("cn={0}").type(STRING).description("Used with `search-and-bind` and `search-and-compare`. Search filter used. Takes one parameter, user ID defined as `{0}`");
    private final FieldDescriptor ldapGroupSearchBase = fieldWithPath("config.groupSearchBase").required().type(STRING).description("Search start point for a user group membership search, use the value `memberOf` to skip group search, and use the memberOf attributes of the user.");
    private final FieldDescriptor ldapGroupSearchFilter = fieldWithPath("config.groupSearchFilter").required().type(STRING).description("Search query filter to find the groups a user belongs to, or for a nested search, groups that a group belongs to");
    private final FieldDescriptor ldapGroupAutoAdd = fieldWithPath("config.autoAddGroups").optional(true).type(BOOLEAN).description("Set to true when `profile_type=groups_as_scopes` to auto create scopes for a user. Ignored for other profiles.");
    private final FieldDescriptor ldapGroupSearchSubtree = fieldWithPath("config.groupSearchSubTree").optional(true).type(BOOLEAN).description("Boolean value, set to true to search below the search base");
    private final FieldDescriptor ldapGroupMaxSearchDepth = fieldWithPath("config.maxGroupSearchDepth").optional(10).type(NUMBER).description("Set to number of levels a nested group search should go. Set to `1` to disable nested groups.");
    private final FieldDescriptor ldapUserMailAttribute = fieldWithPath("config.mailAttributeName").optional(MAIL).type(STRING).description("The name of the LDAP attribute that contains the user's email address");
    private final FieldDescriptor ldapUserMailSubstitute = fieldWithPath("config.mailSubstitute").optional(null).type(STRING).description("Defines an email pattern containing a `{0}` to generate an email address for an LDAP user during authentication");
    private final FieldDescriptor ldapUserMailSubstituteOverridesLdap = fieldWithPath("config.mailSubstituteOverridesLdap").optional(false).type(BOOLEAN).description("Set to true if you wish to override an LDAP user email address with a generated one");
    private final FieldDescriptor ldapSslSkipVerification = fieldWithPath("config.skipSSLVerification").optional(false).type(BOOLEAN).description("Skips validation of the LDAP cert if set to true.");
    private final FieldDescriptor ldapSslTls = fieldWithPath("config.tlsConfiguration").optional("none").type(STRING).description("Sets the StartTLS options, valid values are `none`, `simple` or `external`");
    private final FieldDescriptor ldapReferral = fieldWithPath("config.referral").optional("follow").type(STRING).description("Configures the UAA LDAP referral behavior. The following values are possible:" +
            "  <ul><li>follow &rarr; Referrals are followed</li>" +
            "  <li>ignore &rarr; Referrals are ignored and the partial result is returned</li>" +
            "  <li>throw  &rarr; An error is thrown and the authentication is aborted</li></ul>" +
            "  Reference: [http://docs.oracle.com/javase/jndi/tutorial/ldap/referral/jndi.html](http://docs.oracle.com/javase/jndi/tutorial/ldap/referral/jndi.html)");
    private final FieldDescriptor ldapGroupsIgnorePartial = fieldWithPath("config.groupsIgnorePartialResults").optional(null).type(BOOLEAN).description("Whether to ignore partial results errors from LDAP when mapping groups");
    private final FieldDescriptor ldapUserDnPattern = fieldWithPath("config.userDNPattern").optional("cn={0},ou=Users,dc=test,dc=com").type(STRING).description("Used with `simple-bind` only. A semi-colon separated lists of DN patterns to construct a DN direct from the user ID without performing a search.");
    private final FieldDescriptor ldapUserDnPatternDelim = fieldWithPath("config.userDNPatternDelimiter").optional(";").type(STRING).description("The delimiter character in between user DN patterns for `simple-bind` authentication.");

    private final FieldDescriptor ldapUserComparePasswordAttributeName = fieldWithPath("config.passwordAttributeName").optional("userPassword").type(STRING).description("Used with `search-and-compare` only. The name of the password attribute in the LDAP directory.");
    private final FieldDescriptor ldapUserCompareEncoder = fieldWithPath("config.passwordEncoder").optional("org.cloudfoundry.identity.uaa.provider.ldap.DynamicPasswordComparator").type(STRING).description("Used with `search-and-compare` only. A fully-qualified Java classname to the password encoder. This encoder is used to properly encode user password to match the one in the LDAP directory.");
    private final FieldDescriptor ldapUserCompareLocal = fieldWithPath("config.localPasswordCompare").optional(null).type(BOOLEAN).description("Set to true if the comparison should be done locally. Setting this value to false implies that rather than retrieving the password, the UAA will run a query to match the password. In order for this query to work, you must know what type of hash/encoding/salt is used for the LDAP password.");
    private final FieldDescriptor ldapGroupRoleAttribute = fieldWithPath("config.groupRoleAttribute").optional("description").type(STRING).description("Used with `groups-as-scopes`, defines the attribute that holds the scope name(s).");
    private final FieldDescriptor ldapAttributeMappingFirstname = fieldWithPath("config.attributeMappings.first_name").optional("givenname").type(STRING).description(GIVEN_NAME_DESC);
    private final FieldDescriptor ldapAttributeMappingLastname = fieldWithPath("config.attributeMappings.family_name").optional("sn").type(STRING).description(FAMILY_NAME_DESC);
    private final FieldDescriptor ldapAttributeMappingPhone = fieldWithPath("config.attributeMappings.phone_number").optional("telephonenumber").type(STRING).description(PHONE_NUMBER_DESC);
    private final FieldDescriptor ldapAttributeMappingUserName = fieldWithPath("config.attributeMappings.user_name").optional("user_name").type(STRING).description("Map `user_name` to the attribute for user name in the provider assertion or token. The default for LDAP is the User Name filter");

    private static final HeaderDescriptor IDENTITY_ZONE_ID_HEADER = headerWithName(IdentityZoneSwitchingFilter.HEADER).description("May include this header to administer another zone if using `zones.<zoneId>.admin` or `uaa.admin` scope against the default UAA zone.").optional();
    private static final HeaderDescriptor IDENTITY_ZONE_SUBDOMAIN_HEADER = headerWithName(IdentityZoneSwitchingFilter.SUBDOMAIN_HEADER).optional().description("If using a `zones.<zoneId>.admin` scope/token, indicates what Identity Zone this request goes to by supplying a subdomain.");
    private final FieldDescriptor[] ldapAllFields = ArrayUtils.addAll(commonProviderFields,
            ldapType,
            ldapOriginKey,
            ldapProfileFile,
            ldapGroupFile,
            ldapUrl,
            ldapBindUserDn,
//        LDAP_BIND_PASSWORD,
            ldapUserSearchBase,
            ldapUserSearchFilter,
            ldapGroupSearchBase,
            ldapGroupSearchFilter,
            ldapGroupAutoAdd,
            ldapGroupSearchSubtree,
            ldapGroupMaxSearchDepth,
            ldapUserMailAttribute,
            ldapUserMailSubstitute,
            ldapUserMailSubstituteOverridesLdap,
            ldapSslSkipVerification,
            ldapSslTls,
            ldapReferral,
            ldapGroupsIgnorePartial,
            ldapUserDnPattern,
            ldapUserDnPatternDelim,
            ldapUserComparePasswordAttributeName,
            ldapUserCompareEncoder,
            ldapUserCompareLocal,
            ldapGroupRoleAttribute,
            ATTRIBUTE_MAPPING,
            ldapAttributeMappingUserName,
            ldapAttributeMappingFirstname,
            ldapAttributeMappingLastname,
            ldapAttributeMappingPhone,
            ATTRIBUTE_MAPPING_EMAIL_VERIFIED_FIELD,
            EXTERNAL_GROUPS_WHITELIST);

    private final FieldDescriptor[] ldapSearchAndCompareGroupsAsScopes = ArrayUtils.addAll(
            commonProviderFields,
            ArrayUtils.addAll(
                    new FieldDescriptor[]{
                            ldapType,
                            ldapOriginKey,
                            ldapProfileFile,
                            ldapGroupFile,
                            ldapUrl,
                            ldapBindUserDn,
                            ldapBindPassword,
                            ldapUserSearchBase,
                            ldapUserSearchFilter,
                            ldapGroupSearchBase,
                            ldapGroupSearchFilter,
                            ldapGroupAutoAdd,
                            ldapGroupSearchSubtree,
                            ldapGroupMaxSearchDepth,
                            ldapUserMailAttribute,
                            ldapUserMailSubstitute,
                            ldapUserMailSubstituteOverridesLdap,
                            ldapSslSkipVerification,
                            ldapSslTls,
                            ldapReferral,
                            ldapGroupsIgnorePartial,
                            ldapUserDnPattern.ignored(),
                            ldapUserDnPatternDelim.ignored(),
                            ldapUserComparePasswordAttributeName,
                            ldapUserCompareEncoder,
                            ldapUserCompareLocal,
                            ldapGroupRoleAttribute,
                            ATTRIBUTE_MAPPING,
                            ldapAttributeMappingUserName,
                            ldapAttributeMappingFirstname,
                            ldapAttributeMappingLastname,
                            ldapAttributeMappingPhone,
                            ATTRIBUTE_MAPPING_EMAIL_VERIFIED_FIELD,
                            EXTERNAL_GROUPS_WHITELIST
                    },
                    ALIAS_FIELDS_LDAP_CREATE
            )
    );

    private final FieldDescriptor[] ldapSimpleBindFields = ArrayUtils.addAll(
            commonProviderFields,
            ArrayUtils.addAll(
                    new FieldDescriptor[]{
                            ldapType,
                            ldapOriginKey,
                            ldapProfileFile,
                            ldapGroupFile,
                            ldapUrl,
                            ldapUserMailAttribute,
                            ldapUserMailSubstitute,
                            ldapUserMailSubstituteOverridesLdap,
                            ldapSslSkipVerification,
                            ldapSslTls,
                            ldapReferral,
                            ldapUserDnPattern,
                            ldapUserDnPatternDelim,
                            ATTRIBUTE_MAPPING,
                            ldapAttributeMappingUserName,
                            ldapAttributeMappingFirstname,
                            ldapAttributeMappingLastname,
                            ldapAttributeMappingPhone,
                            ATTRIBUTE_MAPPING_EMAIL_VERIFIED_FIELD,
                            ldapBindUserDn.ignored(),
                            ldapUserSearchBase.ignored(),
                            ldapUserSearchFilter.ignored(),
                            ldapGroupSearchBase.ignored(),
                            ldapGroupSearchFilter.ignored(),
                            ldapGroupAutoAdd.ignored(),
                            ldapGroupSearchSubtree.ignored(),
                            ldapGroupMaxSearchDepth.ignored(),
                            ldapGroupsIgnorePartial.ignored(),
                            ldapUserComparePasswordAttributeName.ignored(),
                            ldapUserCompareEncoder.ignored(),
                            ldapUserCompareLocal.ignored(),
                            ldapGroupRoleAttribute.ignored(),
                            EXTERNAL_GROUPS_WHITELIST.ignored()
                    },
                    ALIAS_FIELDS_LDAP_CREATE
            )
    );

    private final FieldDescriptor[] ldapSearchAndBindGroupsToScopes = ArrayUtils.addAll(
            commonProviderFields,
            ArrayUtils.addAll(
                    new FieldDescriptor[]{
                            ldapType,
                            ldapOriginKey,
                            ldapProfileFile,
                            ldapGroupFile,
                            ldapUrl,
                            ldapBindUserDn,
                            ldapBindPassword,
                            ldapUserSearchBase,
                            ldapUserSearchFilter,
                            ldapGroupSearchBase,
                            ldapGroupSearchFilter,
                            ldapGroupAutoAdd.ignored(),
                            ldapGroupSearchSubtree,
                            ldapGroupMaxSearchDepth,
                            ldapUserMailAttribute,
                            ldapUserMailSubstitute,
                            ldapUserMailSubstituteOverridesLdap,
                            ldapSslSkipVerification,
                            ldapSslTls,
                            ldapReferral,
                            ldapGroupsIgnorePartial,
                            ldapUserDnPattern.ignored(),
                            ldapUserDnPatternDelim.ignored(),
                            ldapUserComparePasswordAttributeName.ignored(),
                            ldapUserCompareEncoder.ignored(),
                            ldapUserCompareLocal.ignored(),
                            ldapGroupRoleAttribute.ignored(),
                            ATTRIBUTE_MAPPING,
                            ldapAttributeMappingUserName,
                            ldapAttributeMappingFirstname,
                            ldapAttributeMappingLastname,
                            ldapAttributeMappingPhone,
                            ATTRIBUTE_MAPPING_EMAIL_VERIFIED_FIELD,
                            EXTERNAL_GROUPS_WHITELIST
                    },
                    ALIAS_FIELDS_LDAP_CREATE
            )
    );

    @BeforeEach
    void setUp() throws Exception {
        adminToken = testClient.getClientCredentialsOAuthAccessToken(
                "admin",
                "adminsecret",
                "");

        identityProviderProvisioning = webApplicationContext.getBean(JdbcIdentityProviderProvisioning.class);
    }

    @AfterEach
    void clearUaaConfig() {
        webApplicationContext.getBean(JdbcTemplate.class).update("UPDATE identity_provider SET config=null WHERE origin_key='uaa'");
    }

    @Test
    void createSAMLIdentityProvider() throws Exception {
        IdentityProvider identityProvider = getSamlProvider("SAML");
        identityProvider.setSerializeConfigRaw(true);

        FieldDescriptor[] idempotentFields = ArrayUtils.addAll(commonProviderFields, ArrayUtils.addAll(new FieldDescriptor[]{
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
                fieldWithPath("config.groupMappingMode").optional(ExternalGroupMappingMode.EXPLICITLY_MAPPED).type(STRING).description("Either ``EXPLICITLY_MAPPED`` in order to map external groups to OAuth scopes using the group mappings, or ``AS_SCOPES`` to use SAML group names as scopes."),
                fieldWithPath("config.iconUrl").optional(null).type(STRING).description("Reserved for future use"),
                fieldWithPath("config.socketFactoryClassName").optional(null).description("Property is deprecated and value is ignored."),
                fieldWithPath("config.authnContext").optional(null).type(ARRAY).description("List of AuthnContextClassRef to include in the SAMLRequest. If not specified no AuthnContext will be requested."),
                EXTERNAL_GROUPS_WHITELIST,
                fieldWithPath("config.attributeMappings.user_name").optional("NameID").type(STRING).description("Map `user_name` to the attribute for user name in the provider assertion or token. The default for SAML is `NameID`."),
        }, attributeMappingFields));

        Snippet requestFields = requestFields(ArrayUtils.addAll(idempotentFields, ALIAS_FIELDS_CREATE));

        Snippet responseFields = responseFields(
                ArrayUtils.addAll(
                        idempotentFields,
                        ArrayUtils.addAll(
                                new FieldDescriptor[]{
                                        VERSION,
                                        ID,
                                        ADDITIONAL_CONFIGURATION,
                                        IDENTITY_ZONE_ID,
                                        CREATED,
                                        LAST_MODIFIED,
                                        fieldWithPath("config.idpEntityAlias").type(STRING).description("This will be set to ``originKey``"),
                                        fieldWithPath("config.zoneId").type(STRING).description("This will be set to the ID of the zone where the provider is being created")
                                },
                                ALIAS_FIELDS_GET
                        )
                )
        );

        ResultActions resultActionsMetadata = mockMvc.perform(post("/identity-providers")
                .param("rawConfig", "true")
                .header("Authorization", "Bearer " + adminToken)
                .contentType(APPLICATION_JSON)
                .content(serializeExcludingProperties(identityProvider, "id", "version", "created", "last_modified", "identityZoneId", "config.zoneId", "config.idpEntityAlias", "config.additionalConfiguration")))
                .andExpect(status().isCreated());

        resultActionsMetadata.andDo(document("{ClassName}/{methodName}",
                preprocessRequest(prettyPrint()),
                preprocessResponse(prettyPrint()),
                requestHeaders(
                        headerWithName("Authorization").description("Bearer token containing `zones.<zone id>.admin` or `uaa.admin` or `idps.write` (only in the same zone that you are a user of)"),
                        IDENTITY_ZONE_ID_HEADER,
                        IDENTITY_ZONE_SUBDOMAIN_HEADER
                ),
                commonRequestParams,
                requestFields,
                responseFields
        ));

        SamlIdentityProviderDefinition providerDefinition = new SamlIdentityProviderDefinition()
                .setMetaDataLocation(IntegrationTestUtils.EXAMPLE_DOT_COM_SAML_IDP_METADATA)
                .setNameID("urn:oasis:names:tc:SAML:1.1:nameid-format:transient")
                .setLinkText("IDPEndpointsMockTests Saml Provider:" + identityProvider.getOriginKey())
                .setZoneId(IdentityZone.getUaaZoneId());

        identityProvider.setConfig(providerDefinition);
        identityProvider.setOriginKey(identityProvider.getOriginKey() + "MetadataUrl");

        ResultActions resultActionsUrl = mockMvc.perform(post("/identity-providers")
                .param("rawConfig", "true")
                .header("Authorization", "Bearer " + adminToken)
                .contentType(APPLICATION_JSON)
                .content(serializeExcludingProperties(identityProvider, "id", "version", "created", "last_modified", "identityZoneId", "config.zoneId", "config.idpEntityAlias", "config.additionalConfiguration")))
                .andExpect(status().isCreated());

        resultActionsUrl.andDo(document("{ClassName}/{methodName}MetadataUrl",
                preprocessRequest(prettyPrint()),
                preprocessResponse(prettyPrint()),
                requestHeaders(
                        headerWithName("Authorization").description("Bearer token containing `zones.<zone id>.admin` or `uaa.admin` or `idps.write` (only in the same zone that you are a user of)"),
                        IDENTITY_ZONE_ID_HEADER,
                        IDENTITY_ZONE_SUBDOMAIN_HEADER
                ),
                commonRequestParams,
                requestFields,
                responseFields
        ));
    }

    @Test
    void createOAuthIdentityProvider() throws Exception {
        IdentityProvider identityProvider = new IdentityProvider();
        identityProvider.setType(OAUTH20);
        identityProvider.setName("UAA Provider");
        identityProvider.setOriginKey("my-oauth2-provider");
        AbstractExternalOAuthIdentityProviderDefinition definition = new RawExternalOAuthIdentityProviderDefinition();
        definition.setAuthUrl(URI.create("http://auth.url").toURL());
        definition.setTokenUrl(URI.create("http://token.url").toURL());
        definition.setTokenKey("token-key");
        definition.setRelyingPartyId("uaa");
        definition.setRelyingPartySecret("secret");
        definition.setShowLinkText(false);
        definition.setAttributeMappings(getAttributeMappingMap());
        definition.setUserPropagationParameter("username");
        definition.setPkce(true);
        definition.setCacheJwks(true);
        definition.setPerformRpInitiatedLogout(true);
        identityProvider.setConfig(definition);
        identityProvider.setSerializeConfigRaw(true);

        FieldDescriptor[] idempotentFields = ArrayUtils.addAll(commonProviderFields, ArrayUtils.addAll(new FieldDescriptor[]{
                fieldWithPath("type").required().description("`\"" + OAUTH20 + "\"`"),
                fieldWithPath("originKey").required().description("A unique alias for a OAuth provider"),
                fieldWithPath("config.authUrl").required().type(STRING).description("The OAuth 2.0 authorization endpoint URL"),
                fieldWithPath("config.tokenUrl").required().type(STRING).description("The OAuth 2.0 token endpoint URL"),
                fieldWithPath("config.tokenKeyUrl").optional(null).type(STRING).description("The URL of the token key endpoint which renders the JWKS (verification key for validating token signatures)."),
                fieldWithPath("config.cacheJwks").optional(true).type(BOOLEAN).description("<small><mark>UAA 77.11.0</mark></small>. Option to enable caching for the JWKS (verification key for validating token signatures). Setting it to `true` increases UAA performance and is hence recommended. Setting it to `false` forces UAA to fetch the remote JWKS at each token validation, which impacts performance but may be required for when the remote JWKS changes very frequently.").attributes(new Attributes.Attribute("constraints", "Used only if `discoveryUrl` or `tokenKeyUrl` is set.")),
                fieldWithPath("config.tokenKey").optional(null).type(STRING).description("A verification key for validating token signatures, set to null if a `tokenKeyUrl` is provided."),
                fieldWithPath("config.userInfoUrl").optional(null).type(STRING).description("A URL for fetching user info attributes when queried with the obtained token authorization."),
                fieldWithPath("config.showLinkText").optional(true).type(BOOLEAN).description("A flag controlling whether a link to this provider's login will be shown on the UAA login page"),
                fieldWithPath("config.linkText").optional(null).type(STRING).description("Text to use for the login link to the provider"),
                fieldWithPath("config.relyingPartyId").required().type(STRING).description("The client ID which is registered with the external OAuth provider for use by the UAA"),
                fieldWithPath("config.skipSslValidation").optional(null).type(BOOLEAN).description("A flag controlling whether SSL validation should be skipped when communicating with the external OAuth server"),
                fieldWithPath("config.scopes").optional(null).type(ARRAY).description("What scopes to request on a call to the external OAuth provider"),
                fieldWithPath("config.checkTokenUrl").optional(null).type(OBJECT).description("Reserved for future OAuth use."),
                fieldWithPath("config.logoutUrl").optional(null).type(OBJECT).description("OAuth 2.0 logout endpoint."),
                fieldWithPath("config.responseType").optional("code").type(STRING).description("Response type for the authorize request, will be sent to OAuth server, defaults to `code`"),
                fieldWithPath("config.clientAuthInBody").optional(false).type(BOOLEAN).description("Sends the client credentials in the token retrieval call as body parameters instead of a Basic Authorization header."),
                fieldWithPath("config.pkce").optional(true).type(BOOLEAN).description("A flag controlling whether PKCE (RFC 7636) is active in authorization code flow when requesting tokens from the external provider."),
                fieldWithPath("config.performRpInitiatedLogout").optional(true).type(BOOLEAN).description("A flag controlling whether to log out of the external provider after a successful UAA logout per [OIDC RP-Initiated Logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html)"),
                fieldWithPath("config.issuer").optional(null).type(STRING).description("The OAuth 2.0 token issuer. This value is used to validate the issuer inside the token."),
                fieldWithPath("config.userPropagationParameter").optional("username").type(STRING).description("Name of the request parameter that is used to pass a known username when redirecting to this identity provider from the account chooser"),
                fieldWithPath("config.attributeMappings.user_name").optional("sub").type(STRING).description("Map `user_name` to the attribute for user name in the provider assertion or token. The default for OpenID Connect is `sub`"),
                fieldWithPath("config.groupMappingMode").optional(AbstractExternalOAuthIdentityProviderDefinition.OAuthGroupMappingMode.EXPLICITLY_MAPPED).type(STRING).description("Either ``EXPLICITLY_MAPPED`` in order to map external claim values to OAuth scopes using the group mappings, or ``AS_SCOPES`` to use claim values names as scopes. You need to define also ``external_groups`` for the mapping in order to use this feature."),
                fieldWithPath("config.authMethod").optional("client_secret_basic").type(STRING).description("<small><mark>UAA 77.10.0</mark></small> Define an explicit method to authenticate against the identity provider. Supported values are `client_secret_basic`, `client_secret_post`, `private_key_jwt`, and `none`. Remark: If you switch the method from `client_secret_basic` to `private_key_jwt` or to `none`, your existing `config.relyingPartySecret` will be removed from UAA database. If you want to switch back to `client_secret_basic`, provide again a `config.relyingPartySecret` in the configuration."),
                fieldWithPath("config.jwtClientAuthentication").constrained("Required if `config.authMethod` is set to `private_key_jwt`").type(OBJECT).description("<small><mark>UAA 76.5.0</mark></small> Only effective if relyingPartySecret is not set or null. Creates private_key_jwt client authentication according to OIDC or OAuth2 (RFC 7523) standard. " +
                        "<br>For standard OIDC compliance, set this field to `true`. Alternatively, you can further configure the created JWT for client authentication by setting this parameter to an Object containing sub-parameters, e.g. if your IdP follows OAuth2 standard according to RFC 7523. The supported sub-parameters are" +
                        "<ul><li>    `kid`  <small><mark>UAA 76.18.0</mark></small> Optional custom key from your defined keys, defaults to `activeKeyId` from token policy section</li>" +
                        "<li>        `key`  <small><mark>UAA 77.4.0</mark></small> Optional custom private key, used to generate the client JWT signature, defaults to key from token policy, depending on `kid` </li>" +
                        "<li>        `cert` <small><mark>UAA 77.4.0</mark></small> Optional custom X509 certificate, related to key, used to generate the client JWT with x5t header, defaults to a cert from token policy or omits x5t header </li>" +
                        "<li>        `sub`  Optional custom subject, see RFC 7523, defaults to `relyingPartyId` for OIDC compliance</li>" +
                        "<li>        `iss`  Optional custom issuer, see RFC 7523, defaults to `relyingPartyId` for OIDC compliance</li>" +
                        "<li>        `aud`  Optional custom audience, see RFC 7523, defaults to `tokenUrl` for OIDC compliance</li></ul><p>" +
                        "The values in the list can be a reference to another section in uaa yaml, e.g. define for key a reference like ${\"jwt.client.key\"}. This will load the private key from yaml context jwt.client.key. The advantage is, that you can use a single key for many IdP configurations and the key itself is not persistent in the UAA DB.</p>"),
        }, attributeMappingFields));

        Snippet requestFields = requestFields(
                ArrayUtils.addAll(
                        idempotentFields,
                        ArrayUtils.add(
                                ALIAS_FIELDS_CREATE,
                                relyingPartySecret
                        )
                )
        );
        Snippet responseFields = responseFields(
                ArrayUtils.addAll(
                        idempotentFields,
                        ArrayUtils.addAll(
                                new FieldDescriptor[]{
                                        VERSION,
                                        ID,
                                        ADDITIONAL_CONFIGURATION,
                                        IDENTITY_ZONE_ID,
                                        CREATED,
                                        LAST_MODIFIED,
                                        fieldWithPath("config.externalGroupsWhitelist").optional(null).type(ARRAY).description("Not currently used.")
                                },
                                ALIAS_FIELDS_GET
                        )
                )
        );

        ResultActions resultActions = mockMvc.perform(post("/identity-providers")
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
                        IDENTITY_ZONE_ID_HEADER,
                        IDENTITY_ZONE_SUBDOMAIN_HEADER
                ),
                commonRequestParams,
                requestFields,
                responseFields
        ));
    }

    @Test
    void createOidcIdentityProvider() throws Exception {
        IdentityProvider identityProvider = new IdentityProvider();
        identityProvider.setType(OIDC10);
        identityProvider.setName("UAA Provider");
        identityProvider.setOriginKey("my-oidc-provider-" + new AlphanumericRandomValueStringGenerator().generate().toLowerCase());
        OIDCIdentityProviderDefinition definition = new OIDCIdentityProviderDefinition();
        definition.setDiscoveryUrl(URI.create("https://accounts.google.com/.well-known/openid-configuration").toURL());
        definition.setSkipSslValidation(true);
        definition.setRelyingPartyId("uaa");
        definition.setRelyingPartySecret("secret");
        definition.setShowLinkText(false);
        definition.setPkce(true);
        definition.setCacheJwks(true);
        definition.setPerformRpInitiatedLogout(true);
        definition.setAttributeMappings(getAttributeMappingMap());
        definition.setUserPropagationParameter("username");
        definition.setExternalGroupsWhitelist(Collections.singletonList("uaa.user"));
        List<Prompt> prompts = Arrays.asList(new Prompt("username", "text", "Email"),
                new Prompt("password", "password", "Password"),
                new Prompt("passcode", "password", "Temporary Authentication Code (Get on at /passcode)"));
        definition.setPrompts(prompts);
        identityProvider.setConfig(definition);
        identityProvider.setSerializeConfigRaw(true);

        FieldDescriptor[] idempotentFields = ArrayUtils.addAll(commonProviderFields, ArrayUtils.addAll(new FieldDescriptor[]{
                fieldWithPath("type").required().description("`\"" + OIDC10 + "\"`"),
                fieldWithPath("originKey").required().description("A unique alias for the OIDC 1.0 provider"),
                fieldWithPath("config.discoveryUrl").optional(null).type(STRING).description("The OpenID Connect Discovery URL, typically ends with /.well-known/openid-configurationmit "),
                fieldWithPath("config.authUrl").optional().type(STRING).description("The OIDC 1.0 authorization endpoint URL. This can be left blank if a discovery URL is provided. If both are provided, this property overrides the discovery URL.").attributes(new Attributes.Attribute("constraints", "Required unless `discoveryUrl` is set.")),
                fieldWithPath("config.tokenUrl").optional().type(STRING).description("The OIDC 1.0 token endpoint URL.  This can be left blank if a discovery URL is provided. If both are provided, this property overrides the discovery URL.").attributes(new Attributes.Attribute("constraints", "Required unless `discoveryUrl` is set.")),
                fieldWithPath("config.tokenKeyUrl").optional(null).type(STRING).description("The URL of the token key endpoint which renders the JWKS (verification key for validating token signatures).  This can be left blank if a discovery URL is provided. If both are provided, this property overrides the discovery URL.").attributes(new Attributes.Attribute("constraints", "Required unless `discoveryUrl` is set.")),
                fieldWithPath("config.cacheJwks").optional(true).type(BOOLEAN).description("<small><mark>UAA 77.11.0</mark></small>. Option to enable caching for the JWKS (verification key for validating token signatures). Setting it to `true` increases UAA performance and is hence recommended. Setting it to `false` forces UAA to fetch the remote JWKS at each token validation, which impacts performance but may be required for when the remote JWKS changes very frequently.").attributes(new Attributes.Attribute("constraints", "Used only if `discoveryUrl` or `tokenKeyUrl` is set.")),
                fieldWithPath("config.tokenKey").optional(null).type(STRING).description("A verification key for validating token signatures. We recommend not setting this as it will not allow for key rotation.  This can be left blank if a discovery URL is provided. If both are provided, this property overrides the discovery URL.").attributes(new Attributes.Attribute("constraints", "Required unless `discoveryUrl` is set.")),
                fieldWithPath("config.showLinkText").optional(true).type(BOOLEAN).description("A flag controlling whether a link to this provider's login will be shown on the UAA login page"),
                fieldWithPath("config.linkText").optional(null).type(STRING).description("Text to use for the login link to the provider"),
                fieldWithPath("config.relyingPartyId").required().type(STRING).description("The client ID which is registered with the external OAuth provider for use by the UAA"),
                fieldWithPath("config.skipSslValidation").optional(null).type(BOOLEAN).description("A flag controlling whether SSL validation should be skipped when communicating with the external OAuth server"),
                fieldWithPath("config.scopes").optional(null).type(ARRAY).description("What scopes to request on a call to the external OAuth/OpenID provider. For example, can provide " +
                        "`openid`, `roles`, or `profile` to request ID token, scopes populated in the ID token external groups attribute mappings, or the user profile information, respectively."),
                fieldWithPath("config.checkTokenUrl").optional(null).type(OBJECT).description("Reserved for future OAuth/OIDC use."),
                fieldWithPath("config.clientAuthInBody").optional(false).type(BOOLEAN).description("Only effective if relyingPartySecret is defined. Sends the client credentials in the token retrieval call as body parameters instead of a Basic Authorization header. It is recommended to set `jwtClientAuthentication:true` instead."),
                fieldWithPath("config.pkce").optional(true).type(BOOLEAN).description("A flag controlling whether PKCE (RFC 7636) is active in authorization code flow when requesting tokens from the external provider."),
                fieldWithPath("config.performRpInitiatedLogout").optional(true).type(BOOLEAN).description("A flag controlling whether to log out of the external provider after a successful UAA logout per [OIDC RP-Initiated Logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html)"),
                fieldWithPath("config.userInfoUrl").optional(null).type(OBJECT).description("Reserved for future OIDC use.  This can be left blank if a discovery URL is provided. If both are provided, this property overrides the discovery URL."),
                fieldWithPath("config.logoutUrl").optional(null).type(OBJECT).description("OIDC logout endpoint. This can be left blank if a discovery URL is provided. If both are provided, this property overrides the discovery URL."),
                fieldWithPath("config.responseType").optional("code").type(STRING).description("Response type for the authorize request, defaults to `code`, but can be `code id_token` if the OIDC server can return an id_token as a query parameter in the redirect."),
                fieldWithPath("config.issuer").optional(null).type(STRING).description("The OAuth 2.0 token issuer. This value is used to validate the issuer inside the token."),
                fieldWithPath("config.userPropagationParameter").optional("username").type(STRING).description("Name of the request parameter that is used to pass a known username when redirecting to this identity provider from the account chooser"),
                GROUP_WHITELIST,
                fieldWithPath("config.passwordGrantEnabled").optional(false).type(BOOLEAN).description("Enable Resource Owner Password Grant flow for this identity provider."),
                fieldWithPath("config.tokenExchangeEnabled").optional(false).type(BOOLEAN).description("Enable JWT Bearer Token Exchange Grant flow for this identity provider."),
                fieldWithPath("config.setForwardHeader").optional(false).type(BOOLEAN).description("Only effective if Password Grant enabled. Set X-Forward-For header in Password Grant request to this identity provider."),
                fieldWithPath("config.authMethod").optional("client_secret_basic").type(STRING).description("<small><mark>UAA 77.10.0</mark></small> Define an explicit method to authenticate against the identity provider. Supported values are `client_secret_basic`, `client_secret_post`, `private_key_jwt`, and `none`. Remark: If you switch the method from `client_secret_basic` to `private_key_jwt` or to `none`, your existing `config.relyingPartySecret` will be removed from UAA database. If you want to switch back to `client_secret_basic`, provide again a `config.relyingPartySecret` in the configuration."),
                fieldWithPath("config.jwtClientAuthentication").constrained("Required if `config.authMethod` is set to `private_key_jwt`").type(OBJECT).description("<small><mark>UAA 76.5.0</mark></small> Only effective if relyingPartySecret is not set or null. Creates private_key_jwt client authentication according to OIDC or OAuth2 (RFC 7523) standard. " +
                        "<br>For standard OIDC compliance, set this field to `true`. Alternatively, you can further configure the created JWT for client authentication by setting this parameter to an Object containing sub-parameters, e.g. if your IdP follows OAuth2 standard according to RFC 7523. The supported sub-parameters are" +
                        "<ul><li>    `kid`  <small><mark>UAA 76.18.0</mark></small> Optional custom key from your defined keys, defaults to `activeKeyId` from token policy section</li>" +
                        "<li>        `key`  <small><mark>UAA 77.4.0</mark></small> Optional custom private key, used to generate the client JWT signature, defaults to key from token policy, depending on `kid` </li>" +
                        "<li>        `cert` <small><mark>UAA 77.4.0</mark></small> Optional custom X509 certificate, related to key, used to generate the client JWT with x5t header, defaults to a cert from token policy or omits x5t header </li>" +
                        "<li>        `sub`  Optional custom subject, see RFC 7523, defaults to `relyingPartyId` for OIDC compliance</li>" +
                        "<li>        `iss`  Optional custom issuer, see RFC 7523, defaults to `relyingPartyId` for OIDC compliance</li>" +
                        "<li>        `aud`  Optional custom audience, see RFC 7523, defaults to `tokenUrl` for OIDC compliance</li></ul><p>" +
                        "The values in the list can be a reference to another section in uaa yaml, e.g. define for key a reference like ${\"jwt.client.key\"}. This will load the private key from yaml context jwt.client.key. The advantage is, that you can use a single key for many IdP configurations and the key itself is not persistent in the UAA DB.</p>"),
                fieldWithPath("config.attributeMappings.user_name").optional("sub").type(STRING).description("Map `user_name` to the attribute for user name in the provider assertion or token. The default for OpenID Connect is `sub`."),
                fieldWithPath("config.additionalAuthzParameters").optional(null).type(OBJECT).description("<small><mark>UAA 76.17.0</mark></small>Map of key-value pairs that are added as additional parameters for grant type `authorization_code`. For example, configure an entry with key `token_format` and value `jwt`."),
                fieldWithPath("config.prompts[]").optional(null).type(ARRAY).description("List of fields that users are prompted on to the OIDC provider through the password grant flow. Defaults to username, password, and passcode. Any additional prompts beyond username, password, and passcode will be forwarded on to the OIDC provider."),
                fieldWithPath("config.prompts[].name").optional(null).type(STRING).description("Name of field"),
                fieldWithPath("config.prompts[].type").optional(null).type(STRING).description("What kind of field this is (e.g. text or password)"),
                fieldWithPath("config.prompts[].text").optional(null).type(STRING).description("Actual text displayed on prompt for field")
        }, attributeMappingFields));

        Snippet requestFields = requestFields(
                ArrayUtils.addAll(
                        idempotentFields,
                        ArrayUtils.add(
                                ALIAS_FIELDS_CREATE,
                                relyingPartySecret
                        )
                )
        );
        Snippet responseFields = responseFields(
                ArrayUtils.addAll(
                        idempotentFields,
                        ArrayUtils.addAll(
                                new FieldDescriptor[]{
                                        VERSION,
                                        ID,
                                        ADDITIONAL_CONFIGURATION,
                                        IDENTITY_ZONE_ID,
                                        CREATED,
                                        LAST_MODIFIED,
                                },
                                ALIAS_FIELDS_GET
                        )
                )
        );

        ResultActions resultActions = mockMvc.perform(post("/identity-providers")
                .param("rawConfig", "true")
                .header("Authorization", "Bearer " + adminToken)
                .contentType(APPLICATION_JSON)
                .content(serializeExcludingProperties(identityProvider, "id", "version", "created", "last_modified", "identityZoneId", "config.checkTokenUrl", "config.additionalConfiguration")))
                .andDo(print())
                .andExpect(status().isCreated());

        resultActions.andDo(document("{ClassName}/{methodName}",
                preprocessRequest(prettyPrint()),
                preprocessResponse(prettyPrint()),
                requestHeaders(
                        headerWithName("Authorization").description("Bearer token containing `zones.<zone id>.admin` or `uaa.admin` or `idps.write` (only in the same zone that you are a user of)"),
                        IDENTITY_ZONE_ID_HEADER,
                        IDENTITY_ZONE_SUBDOMAIN_HEADER
                ),
                commonRequestParams,
                requestFields,
                responseFields
        ));
    }

    @Test
    void create_Simple_Bind_LDAPIdentityProvider() throws Exception {
        IdentityProvider identityProvider = MultitenancyFixture.identityProvider(OriginKeys.LDAP, "");
        identityProvider.setType(LDAP);

        LdapIdentityProviderDefinition providerDefinition = new LdapIdentityProviderDefinition();
        providerDefinition.setLdapProfileFile("ldap/ldap-simple-bind.xml");
        providerDefinition.setLdapGroupFile("ldap/ldap-groups-null.xml");
        providerDefinition.setBaseUrl(ldapContainer.getUrl());
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
    void create_SearchAndBind_Groups_Map_ToScopes_LDAPIdentityProvider() throws Exception {
        IdentityProvider identityProvider = MultitenancyFixture.identityProvider(OriginKeys.LDAP, "");
        identityProvider.setType(LDAP);

        LdapIdentityProviderDefinition providerDefinition = new LdapIdentityProviderDefinition();
        providerDefinition.setLdapProfileFile("ldap/ldap-search-and-bind.xml");
        providerDefinition.setLdapGroupFile("ldap/ldap-groups-map-to-scopes.xml");
        providerDefinition.setBaseUrl(ldapContainer.getUrl());
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

        FieldDescriptor[] fields = ArrayUtils.add(ldapSearchAndBindGroupsToScopes, ldapBindPassword);
        createLDAPProvider(identityProvider, fields, "create_SearchAndBind_Groups_Map_ToScopes_LDAPIdentityProvider");

    }

    @Test
    void create_SearchAndCompare_Groups_As_Scopes_LDAPIdentityProvider() throws Exception {
        IdentityProvider identityProvider = MultitenancyFixture.identityProvider(OriginKeys.LDAP, "");
        identityProvider.setType(LDAP);

        LdapIdentityProviderDefinition providerDefinition = new LdapIdentityProviderDefinition();
        providerDefinition.setLdapProfileFile("ldap/ldap-search-and-compare.xml");
        providerDefinition.setLdapGroupFile("ldap/ldap-groups-as-scopes.xml");
        providerDefinition.setBaseUrl(ldapContainer.getUrl());
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

        FieldDescriptor[] fields = ldapSearchAndCompareGroupsAsScopes;
        createLDAPProvider(identityProvider, fields, "create_SearchAndCompare_Groups_As_Scopes_LDAPIdentityProvider");

    }

    void createLDAPProvider(IdentityProvider<LdapIdentityProviderDefinition> identityProvider,
            FieldDescriptor[] fields,
            String name) throws Exception {
        Map<String, Object> attributeMappings = new HashedMap(identityProvider.getConfig().getAttributeMappings());
        attributeMappings.put(EMAIL_VERIFIED_ATTRIBUTE_NAME, "emailVerified");
        identityProvider.getConfig().setAttributeMappings(attributeMappings);
        UaaClientDetails admin = new UaaClientDetails(
                "admin",
                null,
                "",
                "client_credentials",
                "uaa.admin",
                "http://redirect.url"
        );
        admin.setClientSecret("adminsecret");

        IdentityZoneCreationResult zone =
                MockMvcUtils.createOtherIdentityZoneAndReturnResult(new AlphanumericRandomValueStringGenerator(8).generate().toLowerCase(),
                        mockMvc,
                        webApplicationContext,
                        admin, identityZoneManager.getCurrentIdentityZoneId());

        Snippet requestFields = requestFields(fields);
        Snippet responseFields = responseFields(ArrayUtils.addAll(
                ldapAllFields,
                ArrayUtils.addAll(
                        new FieldDescriptor[]{
                                VERSION,
                                ID,
                                ADDITIONAL_CONFIGURATION,
                                IDENTITY_ZONE_ID,
                                CREATED,
                                LAST_MODIFIED
                        },
                        ALIAS_FIELDS_GET
                )
        ));

        ResultActions resultActions = mockMvc.perform(post("/identity-providers")
                .header(IdentityZoneSwitchingFilter.SUBDOMAIN_HEADER, zone.getIdentityZone().getSubdomain())
                .param("rawConfig", "true")
                .header("Authorization", "Bearer " + zone.getZoneAdminToken())
                .contentType(APPLICATION_JSON)
                .content(serializeExcludingProperties(identityProvider, "id", "version", "created", "last_modified", "identityZoneId", "config.additionalConfiguration")))
                .andExpect(status().isCreated());

        resultActions.andDo(document("{ClassName}/" + name,
                preprocessRequest(prettyPrint()),
                preprocessResponse(prettyPrint()),
                requestHeaders(
                        headerWithName("Authorization").description("Bearer token containing `zones.<zone id>.admin` or `uaa.admin` or `idps.write` (only in the same zone that you are a user of)"),
                        IDENTITY_ZONE_ID_HEADER,
                        IDENTITY_ZONE_SUBDOMAIN_HEADER
                ),
                commonRequestParams,
                requestFields,
                responseFields
        ));

        mockMvc.perform(
                post("/login.do")
                        .header("Host", zone.getIdentityZone().getSubdomain() + ".localhost")
                        .with(cookieCsrf())
                        .param("username", "marissa4")
                        .param("password", "ldap4")
        )
        .andExpect(status().isFound())
                .andExpect(redirectedUrl("/"));
    }

    @Test
    void getAllIdentityProviders() throws Exception {
        Snippet responseFields = responseFields(
                fieldWithPath("[].type").description("Type of the identity provider."),
                fieldWithPath("[].originKey").description("Unique identifier for the identity provider."),
                fieldWithPath("[].name").description(NAME_DESC),
                fieldWithPath("[].config").description(CONFIG_DESCRIPTION),
                fieldWithPath("[]." + FIELD_ALIAS_ID).description(ALIAS_ID_DESC).attributes(key("constraints").value("Optional")).optional().type(STRING),
                fieldWithPath("[]." + FIELD_ALIAS_ZID).description(ALIAS_ZID_DESC).attributes(key("constraints").value("Optional")).optional().type(STRING),

                fieldWithPath("[].version").description(VERSION_DESC),
                fieldWithPath("[].active").description(ACTIVE_DESC),

                fieldWithPath("[].id").description(ID_DESC),
                fieldWithPath("[].identityZoneId").description(IDENTITY_ZONE_ID_DESC),
                fieldWithPath("[].created").description(CREATED_DESC),
                fieldWithPath("[].last_modified").description(LAST_MODIFIED_DESC)
        );

        mockMvc.perform(get("/identity-providers")
                .param("rawConfig", "false")
                .header("Authorization", "Bearer " + adminToken)
                .contentType(APPLICATION_JSON))
                .andExpect(status().isOk())
                .andDo(document("{ClassName}/{methodName}",
                        preprocessResponse(prettyPrint()),
                        requestHeaders(
                                headerWithName("Authorization").description("Bearer token containing `zones.<zone id>.admin` or `zones.<zone id>.idps.read` or `uaa.admin` or `idps.read` (only in the same zone that you are a user of)"),
                                headerWithName("X-Identity-Zone-Id").description("May include this header to administer another zone if using `zones.<zoneId>.admin` or `zones.<zone id>.idps.read` or `uaa.admin` scope against the default UAA zone.").optional(),
                                IDENTITY_ZONE_SUBDOMAIN_HEADER
                        ),
                        commonRequestParams,
                        responseFields));
    }

    @Test
    void getFilteredIdentityProviders() throws Exception {
        Snippet responseFields = responseFields(
                fieldWithPath("[].type").description("Type of the identity provider."),
                fieldWithPath("[].originKey").description("Unique identifier for the identity provider."),
                fieldWithPath("[].name").description(NAME_DESC),
                fieldWithPath("[].config").description(CONFIG_DESCRIPTION),
                fieldWithPath("[]." + FIELD_ALIAS_ID).description(ALIAS_ID_DESC).attributes(key("constraints").value("Optional")).optional().type(STRING),
                fieldWithPath("[]." + FIELD_ALIAS_ZID).description(ALIAS_ZID_DESC).attributes(key("constraints").value("Optional")).optional().type(STRING),

                fieldWithPath("[].version").description(VERSION_DESC),
                fieldWithPath("[].active").description(ACTIVE_DESC),

                fieldWithPath("[].id").description(ID_DESC),
                fieldWithPath("[].identityZoneId").description(IDENTITY_ZONE_ID_DESC),
                fieldWithPath("[].created").description(CREATED_DESC),
                fieldWithPath("[].last_modified").description(LAST_MODIFIED_DESC)
        );

        mockMvc.perform(get("/identity-providers")
                .param("rawConfig", "false")
                .param("active_only", "false")
                .param("originKey", "my-oauth2-provider")
                .header("Authorization", "Bearer " + adminToken)
                .contentType(APPLICATION_JSON))
                .andExpect(status().isOk())
                .andDo(document("{ClassName}/{methodName}",
                        preprocessResponse(prettyPrint()),
                        requestHeaders(
                                headerWithName("Authorization").description("Bearer token containing `zones.<zone id>.admin` or `zones.<zone id>.idps.read` or `uaa.admin` or `idps.read` (only in the same zone that you are a user of)"),
                                headerWithName("X-Identity-Zone-Id").description("May include this header to administer another zone if using `zones.<zoneId>.admin` or `zones.<zone id>.idps.read` or `uaa.admin` scope against the default UAA zone.").optional(),
                                IDENTITY_ZONE_SUBDOMAIN_HEADER
                        ),
                        queryParameters(
                                parameterWithName("rawConfig").optional("false").type(BOOLEAN).description("Flag indicating whether the response should use raw, unescaped JSON for the `config` field of the IDP, rather than the default behavior of encoding the JSON as a string."),
                                parameterWithName("active_only").optional("false").type(BOOLEAN).description("Flag indicating whether only active IdPs should be returned or all."),
                                parameterWithName("originKey").optional(null).type(STRING).description("<small><mark>UAA 77.10.0</mark></small> Return only IdPs with specific origin.")
                        ),
                        responseFields));
    }

    @Test
    void getIdentityProvider() throws Exception {
        IdentityProvider identityProvider = JsonUtils.readValue(mockMvc.perform(post("/identity-providers")
                .header("Authorization", "Bearer " + adminToken)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(getSamlProvider("saml-for-get"))))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString(), IdentityProvider.class);

        mockMvc.perform(get("/identity-providers/{id}", identityProvider.getId())
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
                                headerWithName("X-Identity-Zone-Id").description("May include this header to administer another zone if using `zones.<zoneId>.admin` or `zones.<zone id>.idps.read` or `uaa.admin` scope against the default UAA zone.").optional(),
                                IDENTITY_ZONE_SUBDOMAIN_HEADER
                        ),
                        commonRequestParams,
                        responseFields(getCommonProviderFieldsAnyType())));

        deleteIdentityProviderHelper(identityProvider.getId());
    }

    @Test
    void updateIdentityProvider() throws Exception {
        IdentityProvider identityProvider = identityProviderProvisioning.retrieveByOrigin(OriginKeys.UAA, identityZoneManager.getCurrentIdentityZoneId());

        UaaIdentityProviderDefinition config = new UaaIdentityProviderDefinition();
        config.setLockoutPolicy(new LockoutPolicy(8, 8, 8));
        identityProvider.setConfig(config);
        identityProvider.setSerializeConfigRaw(true);

        FieldDescriptor[] idempotentFields = ArrayUtils.addAll(commonProviderFields,
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
                fieldWithPath("config.disableInternalUserManagement").optional(null).type(BOOLEAN).description("When set to true, user management is disabled for this provider, defaults to false").optional());

        Snippet requestFields = requestFields(ArrayUtils.addAll(idempotentFields, ALIAS_FIELDS_UPDATE));

        Snippet responseFields = responseFields(
                ArrayUtils.addAll(
                        idempotentFields,
                        ArrayUtils.addAll(
                                new FieldDescriptor[]{
                                        VERSION,
                                        ID,
                                        ADDITIONAL_CONFIGURATION,
                                        IDENTITY_ZONE_ID,
                                        CREATED,
                                        LAST_MODIFIED,
                                },
                                ALIAS_FIELDS_GET
                        )
                )
        );

        mockMvc.perform(put("/identity-providers/{id}", identityProvider.getId())
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
                                IDENTITY_ZONE_ID_HEADER,
                                IDENTITY_ZONE_SUBDOMAIN_HEADER
                        ),
                        commonRequestParams,
                        requestFields,
                        responseFields));
    }

    @Test
    void patchIdentityProviderStatus() throws Exception {
        IdentityProvider identityProvider = identityProviderProvisioning.retrieveByOrigin(OriginKeys.UAA, identityZoneManager.getCurrentIdentityZoneId());
        identityProvider.setConfig(new UaaIdentityProviderDefinition(new PasswordPolicy(0, 20, 0, 0, 0, 0, 0), null));
        identityProviderProvisioning.update(identityProvider, identityProvider.getIdentityZoneId());
        IdentityProviderStatus identityProviderStatus = new IdentityProviderStatus();
        identityProviderStatus.setRequirePasswordChange(true);

        FieldDescriptor[] idempotentFields = new FieldDescriptor[]{
                fieldWithPath("requirePasswordChange").required().description("Set to `true` in order to force password change for all users. The `passwordNewerThan` property in PasswordPolicy of the IdentityProvider will be updated with current system time. If the user's passwordLastModified is older than this value, the password is expired.")
        };

        Snippet requestFields = requestFields(idempotentFields);
        Snippet responseFields = responseFields(idempotentFields);

        mockMvc.perform(patch("/identity-providers/{id}/status", identityProvider.getId())
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
                                IDENTITY_ZONE_ID_HEADER,
                                IDENTITY_ZONE_SUBDOMAIN_HEADER
                        ),
                        requestFields,
                        responseFields));
    }

    @Test
    void deleteIdentityProvider() throws Exception {
        IdentityProvider identityProvider = JsonUtils.readValue(mockMvc.perform(post("/identity-providers")
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
                                IDENTITY_ZONE_ID_HEADER,
                                IDENTITY_ZONE_SUBDOMAIN_HEADER
                        ),
                        responseFields(getCommonProviderFieldsAnyType())));
    }

    private ResultActions deleteIdentityProviderHelper(String id) throws Exception {
        return mockMvc.perform(delete("/identity-providers/{id}", id)
                .param("rawConfig", "false")
                .header("Authorization", "Bearer " + adminToken)
                .contentType(APPLICATION_JSON))
                .andExpect(status().isOk());
    }

    private FieldDescriptor[] getCommonProviderFieldsAnyType() {
        return ArrayUtils.addAll(
                commonProviderFields,
                ArrayUtils.addAll(
                        new FieldDescriptor[]{
                                fieldWithPath("type").required().description("Type of the identity provider."),
                                fieldWithPath("originKey").required().description("Unique identifier for the identity provider."),
                                CONFIG,
                                ADDITIONAL_CONFIGURATION,
                                VERSION,
                                ID,
                                IDENTITY_ZONE_ID,
                                CREATED,
                                LAST_MODIFIED
                        },
                        ALIAS_FIELDS_GET
                )
        );
    }

    private IdentityProvider getSamlProvider(String originKey) {
        IdentityProvider<SamlIdentityProviderDefinition> identityProvider = MultitenancyFixture.identityProvider(originKey, IdentityZone.getUaaZoneId());
        identityProvider.setType(SAML);

        SamlIdentityProviderDefinition providerDefinition = new SamlIdentityProviderDefinition()
                .setMetaDataLocation(BootstrapSamlIdentityProviderDataTests.XML_WITHOUT_ID.formatted("http://www.okta.com/" + identityProvider.getOriginKey()))
                .setIdpEntityAlias(identityProvider.getOriginKey())
                .setNameID("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
                .setLinkText("IDPEndpointsMockTests Saml Provider:" + identityProvider.getOriginKey())
                .setZoneId(IdentityZone.getUaaZoneId());
        providerDefinition.setAttributeMappings(getAttributeMappingMap());
        identityProvider.setConfig(providerDefinition);
        return identityProvider;
    }

    private Map<String, Object> getAttributeMappingMap() {
        Map<String, Object> attributeMappings = new HashMap();
        attributeMappings.put(EMAIL_VERIFIED_ATTRIBUTE_NAME, "emailVerified");
        attributeMappings.put(EMAIL_ATTRIBUTE_NAME, "emailAddress");
        attributeMappings.put(GIVEN_NAME_ATTRIBUTE_NAME, "first_name");
        attributeMappings.put(FAMILY_NAME_ATTRIBUTE_NAME, "last_name");
        attributeMappings.put(PHONE_NUMBER_ATTRIBUTE_NAME, "telephone");
        attributeMappings.put(GROUP_ATTRIBUTE_NAME, new String[]{"roles"});
        attributeMappings.put(USER_ATTRIBUTE_PREFIX + "department", "department");
        return attributeMappings;
    }
}
