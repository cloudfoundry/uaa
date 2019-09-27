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
package org.cloudfoundry.identity.uaa.provider.ldap;

import org.cloudfoundry.identity.uaa.impl.config.YamlMapFactoryBean;
import org.cloudfoundry.identity.uaa.impl.config.YamlProcessor;
import org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.LdapUtils;
import org.cloudfoundry.identity.uaa.util.UaaMapUtils;
import org.junit.Before;
import org.junit.Test;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.*;

import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LDAP;
import static org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition.LDAP_PROPERTY_TYPES;
import static org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition.LDAP_SSL_TLS;
import static org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition.LDAP_TLS_EXTERNAL;
import static org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition.LDAP_TLS_NONE;
import static org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition.LDAP_TLS_SIMPLE;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class LdapIdentityProviderDefinitionTest {

    private LdapIdentityProviderDefinition ldapIdentityProviderDefinition;

    @Before
    public void setUp() {

    }

    @Test
    public void test_property_types() {
        assertEquals(String.class, LDAP_PROPERTY_TYPES.get(LDAP_SSL_TLS));
    }

    @Test
    public void test_default_tls_is_none() {
        assertEquals(LDAP_TLS_NONE, new LdapIdentityProviderDefinition().getTlsConfiguration());
    }

    @Test
    public void testEquals() {
        LdapIdentityProviderDefinition ldapIdentityProviderDefinition1 = new LdapIdentityProviderDefinition();
        ldapIdentityProviderDefinition1.setAddShadowUserOnLogin(true);
        LdapIdentityProviderDefinition ldapIdentityProviderDefinition2 = new LdapIdentityProviderDefinition();
        ldapIdentityProviderDefinition2.setAddShadowUserOnLogin(false);
        assertNotEquals(ldapIdentityProviderDefinition1,ldapIdentityProviderDefinition2);

        ldapIdentityProviderDefinition2.setAddShadowUserOnLogin(true);
        assertEquals(ldapIdentityProviderDefinition1,ldapIdentityProviderDefinition2);
    }

    @Test
    public void test_tls_options() {
        ldapIdentityProviderDefinition = new LdapIdentityProviderDefinition();
        ldapIdentityProviderDefinition.setTlsConfiguration(LDAP_TLS_NONE);
        ldapIdentityProviderDefinition.setTlsConfiguration(LDAP_TLS_EXTERNAL);
        ldapIdentityProviderDefinition.setTlsConfiguration(LDAP_TLS_SIMPLE);
        ldapIdentityProviderDefinition.setTlsConfiguration(null);
        assertEquals(LDAP_TLS_NONE, ldapIdentityProviderDefinition.getTlsConfiguration());
        try {
            String tlsConfiguration = "other string";
            ldapIdentityProviderDefinition.setTlsConfiguration(tlsConfiguration);
            fail(tlsConfiguration + " is not a valid TLS configuration option.");
        } catch (IllegalArgumentException ignored) {}
    }

    @Test
    public void test_serialization_of_tls_attribute() {
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
        assertEquals(LDAP_TLS_SIMPLE, deserialized.getTlsConfiguration());
        config = config.replace(",\"tlsConfiguration\":\"simple\"", "");
        deserialized = JsonUtils.readValue(config, LdapIdentityProviderDefinition.class);
        assertEquals(LDAP_TLS_NONE, deserialized.getTlsConfiguration());
    }

    @Test
    public void testSearchAndBindConfiguration() {
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
        assertEquals(ldapIdentityProviderDefinition, deserialized);
        assertEquals("ldap/ldap-search-and-bind.xml", deserialized.getLdapProfileFile());
        assertEquals("ldap/ldap-groups-map-to-scopes.xml", deserialized.getLdapGroupFile());

        ConfigurableEnvironment environment = LdapUtils.getLdapConfigurationEnvironment(deserialized);
        //mail attribute
        assertNotNull(environment.getProperty("ldap.base.mailAttributeName"));
        assertEquals("mail", environment.getProperty("ldap.base.mailAttributeName"));

        //url attribute
        assertNotNull(environment.getProperty("ldap.base.url"));
        assertEquals("ldap://localhost:389/", environment.getProperty("ldap.base.url"));

        //profile file
        assertNotNull(environment.getProperty("ldap.profile.file"));
        assertEquals("ldap/ldap-search-and-bind.xml", environment.getProperty("ldap.profile.file"));

        //group file
        assertNotNull(environment.getProperty("ldap.groups.file"));
        assertEquals("ldap/ldap-groups-map-to-scopes.xml", environment.getProperty("ldap.groups.file"));

        //search sub tree for group
        assertNotNull(environment.getProperty("ldap.groups.searchSubtree"));
        assertEquals(Boolean.TRUE.toString(), environment.getProperty("ldap.groups.searchSubtree"));

        //max search depth for groups
        assertNotNull(environment.getProperty("ldap.groups.maxSearchDepth"));
        assertEquals("100", environment.getProperty("ldap.groups.maxSearchDepth"));

        //skip ssl verification
        assertNotNull(environment.getProperty("ldap.ssl.skipverification"));
        assertEquals("true", environment.getProperty("ldap.ssl.skipverification"));

        //tls configuration
        assertNotNull(environment.getProperty("ldap.ssl.tls"));
        assertEquals(LDAP_TLS_NONE, environment.getProperty("ldap.ssl.tls"));

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
        assertEquals(true, deserialized2.isMailSubstituteOverridesLdap());
        assertEquals("{0}sub", deserialized2.getMailSubstitute());
        assertNotEquals(deserialized, deserialized2);
    }

    public Map<String,Object> getLdapConfig(String config) {
        YamlMapFactoryBean factory = new YamlMapFactoryBean();
        factory.setResolutionMethod(YamlProcessor.ResolutionMethod.OVERRIDE_AND_IGNORE);
        factory.setResources(new Resource[]{new ByteArrayResource(config.getBytes(StandardCharsets.UTF_8))});
        Map<String, Object> map = (Map<String, Object>) factory.getObject().get(LDAP);
        Map<String, Object> result = new HashMap<>();
        result.put(LDAP, map);
        return UaaMapUtils.flatten(result);
    }

    @Test
    public void test_Simple_Bind_Config() throws Exception {
        String config = "ldap:\n" +
            "  profile:\n" +
            "    file: ldap/ldap-simple-bind.xml\n" +
            "  base:\n" +
            "    url: 'ldap://localhost:10389/'\n" +
            "    mailAttributeName: mail\n" +
            "    userDnPattern: 'cn={0},ou=Users,dc=test,dc=com;cn={0},ou=OtherUsers,dc=example,dc=com'";
        LdapIdentityProviderDefinition def = LdapUtils.fromConfig(getLdapConfig(config));

        assertEquals("ldap://localhost:10389/",def.getBaseUrl());
        assertEquals("ldap/ldap-simple-bind.xml",def.getLdapProfileFile());
        assertEquals("cn={0},ou=Users,dc=test,dc=com;cn={0},ou=OtherUsers,dc=example,dc=com", def.getUserDNPattern());
        assertNull(def.getBindPassword());
        assertNull(def.getBindUserDn());
        assertNull(def.getUserSearchBase());
        assertNull(def.getUserSearchFilter());
        assertEquals("mail", def.getMailAttributeName());
        assertNull(def.getMailSubstitute());
        assertFalse(def.isMailSubstituteOverridesLdap());
        assertFalse(def.isSkipSSLVerification());
        assertNull(def.getPasswordAttributeName());
        assertNull(def.getPasswordEncoder());
        assertNull(def.getGroupSearchBase());
        assertNull(def.getGroupSearchFilter());
        assertNull(def.getLdapGroupFile());
        assertTrue(def.isGroupSearchSubTree());
        assertEquals(10, def.getMaxGroupSearchDepth());
        assertTrue(def.isAutoAddGroups());
        assertNull(def.getGroupRoleAttribute());
    }

    @Test
    public void test_Search_and_Bind_Config() throws Exception {
        String config = "ldap:\n" +
            "  profile:\n" +
            "    file: ldap/ldap-search-and-bind.xml\n" +
            "  base:\n" +
            "    url: 'ldap://localhost:10389/'\n" +
            "    mailAttributeName: mail\n" +
            "    userDn: 'cn=admin,ou=Users,dc=test,dc=com'\n" +
            "    password: 'password'\n" +
            "    searchBase: ''\n" +
            "    searchFilter: 'cn={0}'";
        LdapIdentityProviderDefinition def = LdapUtils.fromConfig(getLdapConfig(config));

        assertEquals("ldap://localhost:10389/",def.getBaseUrl());
        assertEquals("ldap/ldap-search-and-bind.xml",def.getLdapProfileFile());
        assertNull(def.getUserDNPattern());
        assertEquals("password", def.getBindPassword());
        assertEquals("cn=admin,ou=Users,dc=test,dc=com", def.getBindUserDn());
        assertEquals("", def.getUserSearchBase());
        assertEquals("cn={0}", def.getUserSearchFilter());
        assertEquals("mail", def.getMailAttributeName());
        assertNull(def.getMailSubstitute());
        assertFalse(def.isMailSubstituteOverridesLdap());
        assertFalse(def.isSkipSSLVerification());
        assertNull(def.getPasswordAttributeName());
        assertNull(def.getPasswordEncoder());
        assertNull(def.getGroupSearchBase());
        assertNull(def.getGroupSearchFilter());
        assertNull(def.getLdapGroupFile());
        assertTrue(def.isGroupSearchSubTree());
        assertEquals(10, def.getMaxGroupSearchDepth());
        assertTrue(def.isAutoAddGroups());
        assertNull(def.getGroupRoleAttribute());
    }

    @Test
    public void test_Search_and_Bind_With_Groups_Config() throws Exception {
        String config = "ldap:\n" +
            "  profile:\n" +
            "    file: ldap/ldap-search-and-bind.xml\n" +
            "  base:\n" +
            "    url: 'ldap://localhost:10389/'\n" +
            "    mailAttributeName: mail\n" +
            "    userDn: 'cn=admin,ou=Users,dc=test,dc=com'\n" +
            "    password: 'password'\n" +
            "    searchBase: ''\n" +
            "    searchFilter: 'cn={0}'\n"+
            "  groups:\n" +
            "    file: ldap/ldap-groups-map-to-scopes.xml\n" +
            "    searchBase: ou=scopes,dc=test,dc=com\n" +
            "    searchSubtree: true\n" +
            "    groupSearchFilter: member={0}\n" +
            "    maxSearchDepth: 30\n" +
            "    autoAdd: true";
        LdapIdentityProviderDefinition def = LdapUtils.fromConfig(getLdapConfig(config));

        assertEquals("ldap://localhost:10389/",def.getBaseUrl());
        assertEquals("ldap/ldap-search-and-bind.xml",def.getLdapProfileFile());
        assertNull(def.getUserDNPattern());
        assertEquals("password", def.getBindPassword());
        assertEquals("cn=admin,ou=Users,dc=test,dc=com", def.getBindUserDn());
        assertEquals("", def.getUserSearchBase());
        assertEquals("cn={0}", def.getUserSearchFilter());
        assertEquals("mail", def.getMailAttributeName());
        assertNull(def.getMailSubstitute());
        assertFalse(def.isMailSubstituteOverridesLdap());
        assertFalse(def.isSkipSSLVerification());
        assertNull(def.getPasswordAttributeName());
        assertNull(def.getPasswordEncoder());
        assertEquals("ou=scopes,dc=test,dc=com", def.getGroupSearchBase());
        assertEquals("member={0}", def.getGroupSearchFilter());
        assertEquals("ldap/ldap-groups-map-to-scopes.xml", def.getLdapGroupFile());
        assertTrue(def.isGroupSearchSubTree());
        assertEquals(30, def.getMaxGroupSearchDepth());
        assertTrue(def.isAutoAddGroups());
        assertNull(def.getGroupRoleAttribute());

    }


    @Test
    public void test_Search_and_Compare_Config() throws Exception {
        String config = "ldap:\n" +
            "  profile:\n" +
            "    file: ldap/ldap-search-and-compare.xml\n" +
            "  base:\n" +
            "    url: 'ldap://localhost:10389/'\n" +
            "    mailAttributeName: mail\n" +
            "    userDn: 'cn=admin,ou=Users,dc=test,dc=com'\n" +
            "    password: 'password'\n" +
            "    searchBase: ''\n" +
            "    searchFilter: 'cn={0}'\n" +
            "    passwordAttributeName: userPassword\n" +
            "    passwordEncoder: org.cloudfoundry.identity.uaa.provider.ldap.DynamicPasswordComparator\n" +
            "    localPasswordCompare: true\n"+
            "    mailSubstitute: 'generated-{0}@company.example.com'\n" +
            "    mailSubstituteOverridesLdap: true\n"+
            "  ssl:\n"+
            "    skipverification: true";

        LdapIdentityProviderDefinition def = LdapUtils.fromConfig(getLdapConfig(config));

        assertEquals("ldap://localhost:10389/",def.getBaseUrl());
        assertEquals("ldap/ldap-search-and-compare.xml",def.getLdapProfileFile());
        assertNull(def.getUserDNPattern());
        assertEquals("password", def.getBindPassword());
        assertEquals("cn=admin,ou=Users,dc=test,dc=com", def.getBindUserDn());
        assertEquals("",def.getUserSearchBase());
        assertEquals("cn={0}",def.getUserSearchFilter());
        assertEquals("mail", def.getMailAttributeName());
        assertEquals("generated-{0}@company.example.com", def.getMailSubstitute());
        assertTrue(def.isMailSubstituteOverridesLdap());
        assertTrue(def.isSkipSSLVerification());
        assertEquals("userPassword", def.getPasswordAttributeName());
        assertEquals("org.cloudfoundry.identity.uaa.provider.ldap.DynamicPasswordComparator", def.getPasswordEncoder());
        assertNull(def.getGroupSearchBase());
        assertNull(def.getGroupSearchFilter());
        assertNull(def.getLdapGroupFile());
        assertTrue(def.isGroupSearchSubTree());
        assertEquals(10, def.getMaxGroupSearchDepth());
        assertTrue(def.isAutoAddGroups());
        assertNull(def.getGroupRoleAttribute());
    }

    @Test
    public void test_Search_and_Compare_With_Groups_1_Config_And_Custom_Attributes() throws Exception {
        String config = "ldap:\n" +
            "  profile:\n" +
            "    file: ldap/ldap-search-and-compare.xml\n" +
            "  base:\n" +
            "    url: 'ldap://localhost:10389/'\n" +
            "    mailAttributeName: mail\n" +
            "    userDn: 'cn=admin,ou=Users,dc=test,dc=com'\n" +
            "    password: 'password'\n" +
            "    searchBase: ''\n" +
            "    searchFilter: 'cn={0}'\n" +
            "    passwordAttributeName: userPassword\n" +
            "    passwordEncoder: org.cloudfoundry.identity.uaa.provider.ldap.DynamicPasswordComparator\n" +
            "    localPasswordCompare: true\n"+
            "    mailSubstitute: 'generated-{0}@company.example.com'\n" +
            "    mailSubstituteOverridesLdap: true\n"+
            "  ssl:\n"+
            "    skipverification: true\n"+
            "  groups:\n" +
            "    file: ldap/ldap-groups-as-scopes.xml\n" +
            "    searchBase: ou=scopes,dc=test,dc=com\n" +
            "    groupRoleAttribute: scopenames\n" +
            "    searchSubtree: false\n" +
            "    groupSearchFilter: member={0}\n" +
            "    maxSearchDepth: 20\n" +
            "    autoAdd: false\n"+
            "  attributeMappings:\n" +
            "    user.attribute.employeeCostCenter: costCenter\n" +
            "    user.attribute.terribleBosses: manager\n";

        LdapIdentityProviderDefinition def = LdapUtils.fromConfig(getLdapConfig(config));

        assertEquals("ldap://localhost:10389/",def.getBaseUrl());
        assertEquals("ldap/ldap-search-and-compare.xml",def.getLdapProfileFile());
        assertNull(def.getUserDNPattern());
        assertEquals("password", def.getBindPassword());
        assertEquals("cn=admin,ou=Users,dc=test,dc=com", def.getBindUserDn());
        assertEquals("",def.getUserSearchBase());
        assertEquals("cn={0}",def.getUserSearchFilter());
        assertEquals("mail", def.getMailAttributeName());
        assertEquals("generated-{0}@company.example.com",def.getMailSubstitute());
        assertTrue(def.isMailSubstituteOverridesLdap());
        assertTrue(def.isSkipSSLVerification());
        assertEquals("userPassword", def.getPasswordAttributeName());
        assertEquals("org.cloudfoundry.identity.uaa.provider.ldap.DynamicPasswordComparator", def.getPasswordEncoder());
        assertEquals("ou=scopes,dc=test,dc=com", def.getGroupSearchBase());
        assertEquals("member={0}", def.getGroupSearchFilter());
        assertEquals("ldap/ldap-groups-as-scopes.xml",def.getLdapGroupFile());
        assertFalse(def.isGroupSearchSubTree());
        assertEquals(20, def.getMaxGroupSearchDepth());
        assertFalse(def.isAutoAddGroups());
        assertEquals("scopenames", def.getGroupRoleAttribute());

        assertEquals(2, def.getAttributeMappings().size());
        assertEquals("costCenter", def.getAttributeMappings().get("user.attribute.employeeCostCenter"));
        assertEquals("manager", def.getAttributeMappings().get("user.attribute.terribleBosses"));
    }

    @Test
    public void testSetEmailDomain() {
        LdapIdentityProviderDefinition def = new LdapIdentityProviderDefinition();
        def.setEmailDomain(Collections.singletonList("test.com"));
        assertEquals("test.com", def.getEmailDomain().get(0));
        def = JsonUtils.readValue(JsonUtils.writeValueAsString(def), LdapIdentityProviderDefinition.class);
        assertEquals("test.com", def.getEmailDomain().get(0));
    }

    @Test
    public void set_external_groups_whitelist() {
        LdapIdentityProviderDefinition def = new LdapIdentityProviderDefinition();
        List<String> externalGroupsWhitelist = new ArrayList<>();
        externalGroupsWhitelist.add("value");
        def.setExternalGroupsWhitelist(externalGroupsWhitelist);
        assertEquals(Collections.singletonList("value"), def.getExternalGroupsWhitelist());
        def = JsonUtils.readValue(JsonUtils.writeValueAsString(def), LdapIdentityProviderDefinition.class);
        assertEquals(Collections.singletonList("value"), def.getExternalGroupsWhitelist());
    }

    @Test
    public void set_user_attributes() {
        LdapIdentityProviderDefinition def = new LdapIdentityProviderDefinition();
        Map<String, Object> attributeMappings = new HashMap<>();
        attributeMappings.put("given_name", "first_name");
        def.setAttributeMappings(attributeMappings);
        assertEquals("first_name", def.getAttributeMappings().get("given_name"));
        def = JsonUtils.readValue(JsonUtils.writeValueAsString(def), LdapIdentityProviderDefinition.class);
        assertEquals("first_name", def.getAttributeMappings().get("given_name"));
    }

    @Test
    public void set_valid_files() {
        ldapIdentityProviderDefinition = new LdapIdentityProviderDefinition();
        for (String s : LdapIdentityProviderDefinition.VALID_PROFILE_FILES) {
            ldapIdentityProviderDefinition.setLdapProfileFile(s);
        }
        for (String s : LdapIdentityProviderDefinition.VALID_GROUP_FILES) {
            ldapIdentityProviderDefinition.setLdapGroupFile(s);
        }
    }

    @Test(expected = IllegalArgumentException.class)
    public void set_unknown_profile_file_throws_error() {
        ldapIdentityProviderDefinition = new LdapIdentityProviderDefinition();
        ldapIdentityProviderDefinition.setLdapProfileFile("some.other.file");
    }

    @Test(expected = IllegalArgumentException.class)
    public void set_unknown_group_file_throws_error() {
        ldapIdentityProviderDefinition = new LdapIdentityProviderDefinition();
        ldapIdentityProviderDefinition.setLdapGroupFile("some.other.file");
    }

    @Test(expected = IllegalArgumentException.class)
    public void deserialize_unknown_profile_file_throws_error() throws Exception {
        String config = "ldap:\n" +
            "  profile:\n" +
            "    file: ldap/ldap-1search-and-compare.xml\n" +
            "  base:\n" +
            "    url: 'ldap://localhost:10389/'\n" +
            "    mailAttributeName: mail\n" +
            "    userDn: 'cn=admin,ou=Users,dc=test,dc=com'\n" +
            "    password: 'password'\n" +
            "    searchBase: ''\n" +
            "    searchFilter: 'cn={0}'\n" +
            "    passwordAttributeName: userPassword\n" +
            "    passwordEncoder: org.cloudfoundry.identity.uaa.provider.ldap.DynamicPasswordComparator\n" +
            "    localPasswordCompare: true\n"+
            "    mailSubstitute: 'generated-{0}@company.example.com'\n" +
            "    mailSubstituteOverridesLdap: true\n"+
            "  ssl:\n"+
            "    skipverification: true";

        LdapUtils.fromConfig(getLdapConfig(config));
    }

    @Test(expected = IllegalArgumentException.class)
    public void deserialize_unknown_group_file_throws_error() throws Exception {
        String config = "ldap:\n" +
            "  profile:\n" +
            "    file: ldap/ldap-search-and-compare.xml\n" +
            "  base:\n" +
            "    url: 'ldap://localhost:10389/'\n" +
            "    mailAttributeName: mail\n" +
            "    userDn: 'cn=admin,ou=Users,dc=test,dc=com'\n" +
            "    password: 'password'\n" +
            "    searchBase: ''\n" +
            "    searchFilter: 'cn={0}'\n" +
            "    passwordAttributeName: userPassword\n" +
            "    passwordEncoder: org.cloudfoundry.identity.uaa.provider.ldap.DynamicPasswordComparator\n" +
            "    localPasswordCompare: true\n"+
            "    mailSubstitute: 'generated-{0}@company.example.com'\n" +
            "    mailSubstituteOverridesLdap: true\n"+
            "  groups:\n" +
            "    file: ldap/ldap-groups1-as-scopes.xml\n" +
            "    searchBase: ou=scopes,dc=test,dc=com\n" +
            "    groupRoleAttribute: scopenames\n" +
            "    searchSubtree: false\n" +
            "    groupSearchFilter: member={0}\n" +
            "    maxSearchDepth: 20\n" +
            "    autoAdd: false\n"+
            "  ssl:\n"+
            "    skipverification: true";

        LdapUtils.fromConfig(getLdapConfig(config));
    }

    @Test
    public void set_correct_password_compare() {
        ldapIdentityProviderDefinition = new LdapIdentityProviderDefinition();
        ldapIdentityProviderDefinition.setPasswordEncoder(DynamicPasswordComparator.class.getName());
    }

    @Test(expected = IllegalArgumentException.class)
    public void set_wrong_password_compare_complains() {
        ldapIdentityProviderDefinition = new LdapIdentityProviderDefinition();
        ldapIdentityProviderDefinition.setPasswordEncoder("some.other.encoder");
    }

    @Test(expected = IllegalArgumentException.class)
    public void deserialize_unknown_comparator_throws_error() throws Exception {
        String config = "ldap:\n" +
            "  profile:\n" +
            "    file: ldap/ldap-search-and-compare.xml\n" +
            "  base:\n" +
            "    url: 'ldap://localhost:10389/'\n" +
            "    mailAttributeName: mail\n" +
            "    userDn: 'cn=admin,ou=Users,dc=test,dc=com'\n" +
            "    password: 'password'\n" +
            "    searchBase: ''\n" +
            "    searchFilter: 'cn={0}'\n" +
            "    passwordAttributeName: userPassword\n" +
            "    passwordEncoder: org.cloudfoundry.identity.uaa.provider.ldap.DynamicPasswordComparator1\n" +
            "    localPasswordCompare: true\n"+
            "    mailSubstitute: 'generated-{0}@company.example.com'\n" +
            "    mailSubstituteOverridesLdap: true\n";

        LdapUtils.fromConfig(getLdapConfig(config));
    }

    @Test
    public void deserialize_correct_comparator() throws Exception {
        String config = "ldap:\n" +
            "  profile:\n" +
            "    file: ldap/ldap-search-and-compare.xml\n" +
            "  base:\n" +
            "    url: 'ldap://localhost:10389/'\n" +
            "    mailAttributeName: mail\n" +
            "    userDn: 'cn=admin,ou=Users,dc=test,dc=com'\n" +
            "    password: 'password'\n" +
            "    searchBase: ''\n" +
            "    searchFilter: 'cn={0}'\n" +
            "    passwordAttributeName: userPassword\n" +
            "    passwordEncoder: org.cloudfoundry.identity.uaa.provider.ldap.DynamicPasswordComparator\n" +
            "    localPasswordCompare: true\n"+
            "    mailSubstitute: 'generated-{0}@company.example.com'\n" +
            "    mailSubstituteOverridesLdap: true\n";

        LdapUtils.fromConfig(getLdapConfig(config));
    }
}
