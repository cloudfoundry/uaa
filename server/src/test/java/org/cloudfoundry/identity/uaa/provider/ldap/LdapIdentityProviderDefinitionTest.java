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
package org.cloudfoundry.identity.uaa.provider.ldap;

import org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.LdapUtils;
import org.cloudfoundry.identity.uaa.util.UaaMapUtils;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.config.YamlMapFactoryBean;
import org.springframework.beans.factory.config.YamlProcessor;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LDAP;
import static org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition.LDAP_PROPERTY_TYPES;
import static org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition.LDAP_SSL_TLS;
import static org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition.LDAP_TLS_EXTERNAL;
import static org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition.LDAP_TLS_NONE;
import static org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition.LDAP_TLS_SIMPLE;

class LdapIdentityProviderDefinitionTest {

    private LdapIdentityProviderDefinition ldapIdentityProviderDefinition;

    @Test
    void property_types() {
        assertThat(LDAP_PROPERTY_TYPES).containsEntry(LDAP_SSL_TLS, String.class);
    }

    @Test
    void default_tls_is_none() {
        assertThat(new LdapIdentityProviderDefinition().getTlsConfiguration()).isEqualTo(LDAP_TLS_NONE);
    }

    @Test
    void equals() {
        LdapIdentityProviderDefinition ldapIdentityProviderDefinition1 = new LdapIdentityProviderDefinition();
        ldapIdentityProviderDefinition1.setAddShadowUserOnLogin(true);
        LdapIdentityProviderDefinition ldapIdentityProviderDefinition2 = new LdapIdentityProviderDefinition();
        ldapIdentityProviderDefinition2.setAddShadowUserOnLogin(false);
        assertThat(ldapIdentityProviderDefinition2).isNotEqualTo(ldapIdentityProviderDefinition1);

        ldapIdentityProviderDefinition2.setAddShadowUserOnLogin(true);
        assertThat(ldapIdentityProviderDefinition2).isEqualTo(ldapIdentityProviderDefinition1);
    }

    @Test
    void noPasswordCastException() {
        LdapIdentityProviderDefinition definition = new LdapIdentityProviderDefinition();
        assertThat(definition.getBindPassword()).isNull();
        definition.setBindPassword("value");
        assertThat(definition.getBindPassword()).isEqualTo("value");
    }

    @Test
    void tls_options() {
        ldapIdentityProviderDefinition = new LdapIdentityProviderDefinition();
        ldapIdentityProviderDefinition.setTlsConfiguration(LDAP_TLS_NONE);
        ldapIdentityProviderDefinition.setTlsConfiguration(LDAP_TLS_EXTERNAL);
        ldapIdentityProviderDefinition.setTlsConfiguration(LDAP_TLS_SIMPLE);
        ldapIdentityProviderDefinition.setTlsConfiguration(null);
        assertThat(ldapIdentityProviderDefinition.getTlsConfiguration()).isEqualTo(LDAP_TLS_NONE);
        String tlsConfiguration = "other string";
        assertThatThrownBy(() ->
                ldapIdentityProviderDefinition.setTlsConfiguration(tlsConfiguration))
                .as(tlsConfiguration + " is not a valid TLS configuration option.")
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void serialization_of_tls_attribute() {
        ldapIdentityProviderDefinition = LdapIdentityProviderDefinition.searchAndBindMapGroupToScopes(
                "ldap://localhost:389/",
                "cn=admin,ou=Users,dc=test,dc=com",
                "adminsecret",
                "dc=test,dc=com",
                "cn={0}",
                "ou=scopes,dc=test,dc=com",
                "member={0}",
                "mail",
                null,
                false,
                true,
                true,
                100,
                true);
        ldapIdentityProviderDefinition.setTlsConfiguration(LDAP_TLS_SIMPLE);
        String config = JsonUtils.writeValueAsString(ldapIdentityProviderDefinition);
        LdapIdentityProviderDefinition deserialized = JsonUtils.readValue(config, LdapIdentityProviderDefinition.class);
        assertThat(deserialized.getTlsConfiguration()).isEqualTo(LDAP_TLS_SIMPLE);
        config = config.replace(",\"tlsConfiguration\":\"simple\"", "");
        deserialized = JsonUtils.readValue(config, LdapIdentityProviderDefinition.class);
        assertThat(deserialized.getTlsConfiguration()).isEqualTo(LDAP_TLS_NONE);
    }

    @Test
    void searchAndBindConfiguration() {
        ldapIdentityProviderDefinition = LdapIdentityProviderDefinition.searchAndBindMapGroupToScopes(
                "ldap://localhost:389/",
                "cn=admin,ou=Users,dc=test,dc=com",
                "adminsecret",
                "dc=test,dc=com",
                "cn={0}",
                "ou=scopes,dc=test,dc=com",
                "member={0}",
                "mail",
                null,
                false,
                true,
                true,
                100,
                true);

        String config = JsonUtils.writeValueAsString(ldapIdentityProviderDefinition);
        LdapIdentityProviderDefinition deserialized = JsonUtils.readValue(config, LdapIdentityProviderDefinition.class);
        assertThat(deserialized).isEqualTo(ldapIdentityProviderDefinition);
        assertThat(deserialized.getLdapProfileFile()).isEqualTo("ldap/ldap-search-and-bind.xml");
        assertThat(deserialized.getLdapGroupFile()).isEqualTo("ldap/ldap-groups-map-to-scopes.xml");

        ConfigurableEnvironment environment = LdapUtils.getLdapConfigurationEnvironment(deserialized);
        //mail attribute
        assertThat(environment.getProperty("ldap.base.mailAttributeName")).isNotNull()
                .isEqualTo("mail");

        //url attribute
        assertThat(environment.getProperty("ldap.base.url")).isNotNull()
                .isEqualTo("ldap://localhost:389/");

        //profile file
        assertThat(environment.getProperty("ldap.profile.file")).isNotNull()
                .isEqualTo("ldap/ldap-search-and-bind.xml");

        //group file
        assertThat(environment.getProperty("ldap.groups.file")).isNotNull()
                .isEqualTo("ldap/ldap-groups-map-to-scopes.xml");

        //search sub tree for group
        assertThat(environment.getProperty("ldap.groups.searchSubtree")).isNotNull()
                .isEqualTo(Boolean.TRUE.toString());

        //max search depth for groups
        assertThat(environment.getProperty("ldap.groups.maxSearchDepth")).isNotNull()
                .isEqualTo("100");

        //skip ssl verification
        assertThat(environment.getProperty("ldap.ssl.skipverification")).isNotNull()
                .isEqualTo("true");

        //tls configuration
        assertThat(environment.getProperty("ldap.ssl.tls")).isNotNull()
                .isEqualTo(LDAP_TLS_NONE);

        ldapIdentityProviderDefinition = LdapIdentityProviderDefinition.searchAndBindMapGroupToScopes(
                "ldap://localhost:389/",
                "cn=admin,ou=Users,dc=test,dc=com",
                "adminsecret",
                "dc=test,dc=com",
                "cn={0}",
                "ou=scopes,dc=test,dc=com",
                "member={0}",
                "mail",
                "{0}sub",
                true,
                true,
                true,
                100,
                true);

        config = JsonUtils.writeValueAsString(ldapIdentityProviderDefinition);
        LdapIdentityProviderDefinition deserialized2 = JsonUtils.readValue(config, LdapIdentityProviderDefinition.class);
        assertThat(deserialized2.isMailSubstituteOverridesLdap()).isTrue();
        assertThat(deserialized2.getMailSubstitute()).isEqualTo("{0}sub");
        assertThat(deserialized2).isNotEqualTo(deserialized);
    }

    public Map<String, Object> getLdapConfig(String config) {
        YamlMapFactoryBean factory = new YamlMapFactoryBean();
        factory.setResolutionMethod(YamlProcessor.ResolutionMethod.OVERRIDE_AND_IGNORE);
        factory.setResources(new Resource[]{new ByteArrayResource(config.getBytes(StandardCharsets.UTF_8))});
        Map<String, Object> map = (Map<String, Object>) factory.getObject().get(LDAP);
        Map<String, Object> result = new HashMap<>();
        result.put(LDAP, map);
        return UaaMapUtils.flatten(result);
    }

    @Test
    void simple_bind_config() {
        String config = """
                ldap:
                  profile:
                    file: ldap/ldap-simple-bind.xml
                  base:
                    url: 'ldap://localhost:10389/'
                    mailAttributeName: mail
                    userDnPattern: 'cn={0},ou=Users,dc=test,dc=com;cn={0},ou=OtherUsers,dc=example,dc=com'""";
        LdapIdentityProviderDefinition def = LdapUtils.fromConfig(getLdapConfig(config));

        assertThat(def.getBaseUrl()).isEqualTo("ldap://localhost:10389/");
        assertThat(def.getLdapProfileFile()).isEqualTo("ldap/ldap-simple-bind.xml");
        assertThat(def.getUserDNPattern()).isEqualTo("cn={0},ou=Users,dc=test,dc=com;cn={0},ou=OtherUsers,dc=example,dc=com");
        assertThat(def.getBindPassword()).isNull();
        assertThat(def.getBindUserDn()).isNull();
        assertThat(def.getUserSearchBase()).isNull();
        assertThat(def.getUserSearchFilter()).isNull();
        assertThat(def.getMailAttributeName()).isEqualTo("mail");
        assertThat(def.getMailSubstitute()).isNull();
        assertThat(def.isMailSubstituteOverridesLdap()).isFalse();
        assertThat(def.isSkipSSLVerification()).isFalse();
        assertThat(def.getPasswordAttributeName()).isNull();
        assertThat(def.getPasswordEncoder()).isNull();
        assertThat(def.getGroupSearchBase()).isNull();
        assertThat(def.getGroupSearchFilter()).isNull();
        assertThat(def.getLdapGroupFile()).isNull();
        assertThat(def.isGroupSearchSubTree()).isTrue();
        assertThat(def.getMaxGroupSearchDepth()).isEqualTo(10);
        assertThat(def.isAutoAddGroups()).isTrue();
        assertThat(def.getGroupRoleAttribute()).isNull();
    }

    @Test
    void search_and_bind_config() {
        String config = """
                ldap:
                  profile:
                    file: ldap/ldap-search-and-bind.xml
                  base:
                    url: 'ldap://localhost:10389/'
                    mailAttributeName: mail
                    userDn: 'cn=admin,ou=Users,dc=test,dc=com'
                    password: 'password'
                    searchBase: ''
                    searchFilter: 'cn={0}'""";
        LdapIdentityProviderDefinition def = LdapUtils.fromConfig(getLdapConfig(config));

        assertThat(def.getBaseUrl()).isEqualTo("ldap://localhost:10389/");
        assertThat(def.getLdapProfileFile()).isEqualTo("ldap/ldap-search-and-bind.xml");
        assertThat(def.getUserDNPattern()).isNull();
        assertThat(def.getBindPassword()).isEqualTo("password");
        assertThat(def.getBindUserDn()).isEqualTo("cn=admin,ou=Users,dc=test,dc=com");
        assertThat(def.getUserSearchBase()).isEmpty();
        assertThat(def.getUserSearchFilter()).isEqualTo("cn={0}");
        assertThat(def.getMailAttributeName()).isEqualTo("mail");
        assertThat(def.getMailSubstitute()).isNull();
        assertThat(def.isMailSubstituteOverridesLdap()).isFalse();
        assertThat(def.isSkipSSLVerification()).isFalse();
        assertThat(def.getPasswordAttributeName()).isNull();
        assertThat(def.getPasswordEncoder()).isNull();
        assertThat(def.getGroupSearchBase()).isNull();
        assertThat(def.getGroupSearchFilter()).isNull();
        assertThat(def.getLdapGroupFile()).isNull();
        assertThat(def.isGroupSearchSubTree()).isTrue();
        assertThat(def.getMaxGroupSearchDepth()).isEqualTo(10);
        assertThat(def.isAutoAddGroups()).isTrue();
        assertThat(def.getGroupRoleAttribute()).isNull();
    }

    @Test
    void search_and_bind_with_groups_config() {
        String config = """
                ldap:
                  profile:
                    file: ldap/ldap-search-and-bind.xml
                  base:
                    url: 'ldap://localhost:10389/'
                    mailAttributeName: mail
                    userDn: 'cn=admin,ou=Users,dc=test,dc=com'
                    password: 'password'
                    searchBase: ''
                    searchFilter: 'cn={0}'
                  groups:
                    file: ldap/ldap-groups-map-to-scopes.xml
                    searchBase: ou=scopes,dc=test,dc=com
                    searchSubtree: true
                    groupSearchFilter: member={0}
                    maxSearchDepth: 30
                    autoAdd: true""";
        LdapIdentityProviderDefinition def = LdapUtils.fromConfig(getLdapConfig(config));

        assertThat(def.getBaseUrl()).isEqualTo("ldap://localhost:10389/");
        assertThat(def.getLdapProfileFile()).isEqualTo("ldap/ldap-search-and-bind.xml");
        assertThat(def.getUserDNPattern()).isNull();
        assertThat(def.getBindPassword()).isEqualTo("password");
        assertThat(def.getBindUserDn()).isEqualTo("cn=admin,ou=Users,dc=test,dc=com");
        assertThat(def.getUserSearchBase()).isEmpty();
        assertThat(def.getUserSearchFilter()).isEqualTo("cn={0}");
        assertThat(def.getMailAttributeName()).isEqualTo("mail");
        assertThat(def.getMailSubstitute()).isNull();
        assertThat(def.isMailSubstituteOverridesLdap()).isFalse();
        assertThat(def.isSkipSSLVerification()).isFalse();
        assertThat(def.getPasswordAttributeName()).isNull();
        assertThat(def.getPasswordEncoder()).isNull();
        assertThat(def.getGroupSearchBase()).isEqualTo("ou=scopes,dc=test,dc=com");
        assertThat(def.getGroupSearchFilter()).isEqualTo("member={0}");
        assertThat(def.getLdapGroupFile()).isEqualTo("ldap/ldap-groups-map-to-scopes.xml");
        assertThat(def.isGroupSearchSubTree()).isTrue();
        assertThat(def.getMaxGroupSearchDepth()).isEqualTo(30);
        assertThat(def.isAutoAddGroups()).isTrue();
        assertThat(def.getGroupRoleAttribute()).isNull();
    }

    @Test
    void search_and_compare_config() {
        String config = """
                ldap:
                  profile:
                    file: ldap/ldap-search-and-compare.xml
                  base:
                    url: 'ldap://localhost:10389/'
                    mailAttributeName: mail
                    userDn: 'cn=admin,ou=Users,dc=test,dc=com'
                    password: 'password'
                    searchBase: ''
                    searchFilter: 'cn={0}'
                    passwordAttributeName: userPassword
                    passwordEncoder: org.cloudfoundry.identity.uaa.provider.ldap.DynamicPasswordComparator
                    localPasswordCompare: true
                    mailSubstitute: 'generated-{0}@company.example.com'
                    mailSubstituteOverridesLdap: true
                  ssl:
                    skipverification: true""";

        LdapIdentityProviderDefinition def = LdapUtils.fromConfig(getLdapConfig(config));

        assertThat(def.getBaseUrl()).isEqualTo("ldap://localhost:10389/");
        assertThat(def.getLdapProfileFile()).isEqualTo("ldap/ldap-search-and-compare.xml");
        assertThat(def.getUserDNPattern()).isNull();
        assertThat(def.getBindPassword()).isEqualTo("password");
        assertThat(def.getBindUserDn()).isEqualTo("cn=admin,ou=Users,dc=test,dc=com");
        assertThat(def.getUserSearchBase()).isEmpty();
        assertThat(def.getUserSearchFilter()).isEqualTo("cn={0}");
        assertThat(def.getMailAttributeName()).isEqualTo("mail");
        assertThat(def.getMailSubstitute()).isEqualTo("generated-{0}@company.example.com");
        assertThat(def.isMailSubstituteOverridesLdap()).isTrue();
        assertThat(def.isSkipSSLVerification()).isTrue();
        assertThat(def.getPasswordAttributeName()).isEqualTo("userPassword");
        assertThat(def.getPasswordEncoder()).isEqualTo("org.cloudfoundry.identity.uaa.provider.ldap.DynamicPasswordComparator");
        assertThat(def.getGroupSearchBase()).isNull();
        assertThat(def.getGroupSearchFilter()).isNull();
        assertThat(def.getLdapGroupFile()).isNull();
        assertThat(def.isGroupSearchSubTree()).isTrue();
        assertThat(def.getMaxGroupSearchDepth()).isEqualTo(10);
        assertThat(def.isAutoAddGroups()).isTrue();
        assertThat(def.getGroupRoleAttribute()).isNull();
    }

    @Test
    void search_and_compare_with_groups_1_config_and_custom_attributes() {
        String config = """
                ldap:
                  profile:
                    file: ldap/ldap-search-and-compare.xml
                  base:
                    url: 'ldap://localhost:10389/'
                    mailAttributeName: mail
                    userDn: 'cn=admin,ou=Users,dc=test,dc=com'
                    password: 'password'
                    searchBase: ''
                    searchFilter: 'cn={0}'
                    passwordAttributeName: userPassword
                    passwordEncoder: org.cloudfoundry.identity.uaa.provider.ldap.DynamicPasswordComparator
                    localPasswordCompare: true
                    mailSubstitute: 'generated-{0}@company.example.com'
                    mailSubstituteOverridesLdap: true
                  ssl:
                    skipverification: true
                  groups:
                    file: ldap/ldap-groups-as-scopes.xml
                    searchBase: ou=scopes,dc=test,dc=com
                    groupRoleAttribute: scopenames
                    searchSubtree: false
                    groupSearchFilter: member={0}
                    maxSearchDepth: 20
                    autoAdd: false
                  attributeMappings:
                    user.attribute.employeeCostCenter: costCenter
                    user.attribute.terribleBosses: manager
                """;

        LdapIdentityProviderDefinition def = LdapUtils.fromConfig(getLdapConfig(config));

        assertThat(def.getBaseUrl()).isEqualTo("ldap://localhost:10389/");
        assertThat(def.getLdapProfileFile()).isEqualTo("ldap/ldap-search-and-compare.xml");
        assertThat(def.getUserDNPattern()).isNull();
        assertThat(def.getBindPassword()).isEqualTo("password");
        assertThat(def.getBindUserDn()).isEqualTo("cn=admin,ou=Users,dc=test,dc=com");
        assertThat(def.getUserSearchBase()).isEmpty();
        assertThat(def.getUserSearchFilter()).isEqualTo("cn={0}");
        assertThat(def.getMailAttributeName()).isEqualTo("mail");
        assertThat(def.getMailSubstitute()).isEqualTo("generated-{0}@company.example.com");
        assertThat(def.isMailSubstituteOverridesLdap()).isTrue();
        assertThat(def.isSkipSSLVerification()).isTrue();
        assertThat(def.getPasswordAttributeName()).isEqualTo("userPassword");
        assertThat(def.getPasswordEncoder()).isEqualTo("org.cloudfoundry.identity.uaa.provider.ldap.DynamicPasswordComparator");
        assertThat(def.getGroupSearchBase()).isEqualTo("ou=scopes,dc=test,dc=com");
        assertThat(def.getGroupSearchFilter()).isEqualTo("member={0}");
        assertThat(def.getLdapGroupFile()).isEqualTo("ldap/ldap-groups-as-scopes.xml");
        assertThat(def.isGroupSearchSubTree()).isFalse();
        assertThat(def.getMaxGroupSearchDepth()).isEqualTo(20);
        assertThat(def.isAutoAddGroups()).isFalse();
        assertThat(def.getGroupRoleAttribute()).isEqualTo("scopenames");

        assertThat(def.getAttributeMappings()).hasSize(2)
                .containsEntry("user.attribute.employeeCostCenter", "costCenter")
                .containsEntry("user.attribute.terribleBosses", "manager");
    }

    @Test
    void setEmailDomain() {
        LdapIdentityProviderDefinition def = new LdapIdentityProviderDefinition();
        def.setEmailDomain(Collections.singletonList("test.com"));
        assertThat(def.getEmailDomain().getFirst()).isEqualTo("test.com");
        def = JsonUtils.readValue(JsonUtils.writeValueAsString(def), LdapIdentityProviderDefinition.class);
        assertThat(def.getEmailDomain().getFirst()).isEqualTo("test.com");
    }

    @Test
    void set_external_groups_whitelist() {
        LdapIdentityProviderDefinition def = new LdapIdentityProviderDefinition();
        List<String> externalGroupsWhitelist = new ArrayList<>();
        externalGroupsWhitelist.add("value");
        def.setExternalGroupsWhitelist(externalGroupsWhitelist);
        assertThat(def.getExternalGroupsWhitelist()).isEqualTo(Collections.singletonList("value"));
        def = JsonUtils.readValue(JsonUtils.writeValueAsString(def), LdapIdentityProviderDefinition.class);
        assertThat(def.getExternalGroupsWhitelist()).isEqualTo(Collections.singletonList("value"));
    }

    @Test
    void set_user_attributes() {
        LdapIdentityProviderDefinition def = new LdapIdentityProviderDefinition();
        Map<String, Object> attributeMappings = new HashMap<>();
        attributeMappings.put("given_name", "first_name");
        def.setAttributeMappings(attributeMappings);
        assertThat(def.getAttributeMappings()).containsEntry("given_name", "first_name");
        def = JsonUtils.readValue(JsonUtils.writeValueAsString(def), LdapIdentityProviderDefinition.class);
        assertThat(def.getAttributeMappings()).containsEntry("given_name", "first_name");
    }

    @Test
    void set_valid_files() {
        ldapIdentityProviderDefinition = new LdapIdentityProviderDefinition();
        for (String s : LdapIdentityProviderDefinition.VALID_PROFILE_FILES) {
            ldapIdentityProviderDefinition.setLdapProfileFile(s);
        }
        for (String s : LdapIdentityProviderDefinition.VALID_GROUP_FILES) {
            ldapIdentityProviderDefinition.setLdapGroupFile(s);
        }
    }

    @Test
    void set_unknown_profile_file_throws_error() {
        ldapIdentityProviderDefinition = new LdapIdentityProviderDefinition();
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() ->
                ldapIdentityProviderDefinition.setLdapProfileFile("some.other.file"));
    }

    @Test
    void set_unknown_group_file_throws_error() {
        ldapIdentityProviderDefinition = new LdapIdentityProviderDefinition();
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() ->
                ldapIdentityProviderDefinition.setLdapGroupFile("some.other.file"));
    }

    @Test
    void deserialize_unknown_profile_file_throws_error() {
        String config = """
                ldap:
                  profile:
                    file: ldap/ldap-1search-and-compare.xml
                  base:
                    url: 'ldap://localhost:10389/'
                    mailAttributeName: mail
                    userDn: 'cn=admin,ou=Users,dc=test,dc=com'
                    password: 'password'
                    searchBase: ''
                    searchFilter: 'cn={0}'
                    passwordAttributeName: userPassword
                    passwordEncoder: org.cloudfoundry.identity.uaa.provider.ldap.DynamicPasswordComparator
                    localPasswordCompare: true
                    mailSubstitute: 'generated-{0}@company.example.com'
                    mailSubstituteOverridesLdap: true
                  ssl:
                    skipverification: true""";
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() ->

                LdapUtils.fromConfig(getLdapConfig(config)));
    }

    @Test
    void deserialize_unknown_group_file_throws_error() {
        String config = """
                ldap:
                  profile:
                    file: ldap/ldap-search-and-compare.xml
                  base:
                    url: 'ldap://localhost:10389/'
                    mailAttributeName: mail
                    userDn: 'cn=admin,ou=Users,dc=test,dc=com'
                    password: 'password'
                    searchBase: ''
                    searchFilter: 'cn={0}'
                    passwordAttributeName: userPassword
                    passwordEncoder: org.cloudfoundry.identity.uaa.provider.ldap.DynamicPasswordComparator
                    localPasswordCompare: true
                    mailSubstitute: 'generated-{0}@company.example.com'
                    mailSubstituteOverridesLdap: true
                  groups:
                    file: ldap/ldap-groups1-as-scopes.xml
                    searchBase: ou=scopes,dc=test,dc=com
                    groupRoleAttribute: scopenames
                    searchSubtree: false
                    groupSearchFilter: member={0}
                    maxSearchDepth: 20
                    autoAdd: false
                  ssl:
                    skipverification: true""";
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() ->

                LdapUtils.fromConfig(getLdapConfig(config)));
    }

    @Test
    void set_correct_password_compare() {
        ldapIdentityProviderDefinition = new LdapIdentityProviderDefinition();
        ldapIdentityProviderDefinition.setPasswordEncoder(DynamicPasswordComparator.class.getName());
    }

    @Test
    void set_wrong_password_compare_complains() {
        ldapIdentityProviderDefinition = new LdapIdentityProviderDefinition();
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() ->
                ldapIdentityProviderDefinition.setPasswordEncoder("some.other.encoder"));
    }

    @Test
    void deserialize_unknown_comparator_throws_error() {
        String config = """
                ldap:
                  profile:
                    file: ldap/ldap-search-and-compare.xml
                  base:
                    url: 'ldap://localhost:10389/'
                    mailAttributeName: mail
                    userDn: 'cn=admin,ou=Users,dc=test,dc=com'
                    password: 'password'
                    searchBase: ''
                    searchFilter: 'cn={0}'
                    passwordAttributeName: userPassword
                    passwordEncoder: org.cloudfoundry.identity.uaa.provider.ldap.DynamicPasswordComparator1
                    localPasswordCompare: true
                    mailSubstitute: 'generated-{0}@company.example.com'
                    mailSubstituteOverridesLdap: true
                """;
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() ->

                LdapUtils.fromConfig(getLdapConfig(config)));
    }

    @Test
    void deserialize_correct_comparator() {
        String config = """
                ldap:
                  profile:
                    file: ldap/ldap-search-and-compare.xml
                  base:
                    url: 'ldap://localhost:10389/'
                    mailAttributeName: mail
                    userDn: 'cn=admin,ou=Users,dc=test,dc=com'
                    password: 'password'
                    searchBase: ''
                    searchFilter: 'cn={0}'
                    passwordAttributeName: userPassword
                    passwordEncoder: org.cloudfoundry.identity.uaa.provider.ldap.DynamicPasswordComparator
                    localPasswordCompare: true
                    mailSubstitute: 'generated-{0}@company.example.com'
                    mailSubstituteOverridesLdap: true
                """;

        LdapUtils.fromConfig(getLdapConfig(config));
    }
}
