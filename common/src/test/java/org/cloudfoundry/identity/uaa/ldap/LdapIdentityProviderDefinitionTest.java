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
package org.cloudfoundry.identity.uaa.ldap;

import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.springframework.core.env.ConfigurableEnvironment;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class LdapIdentityProviderDefinitionTest {

    private LdapIdentityProviderDefinition ldapIdentityProviderDefinition;

    @Before
    public void setUp() throws Exception {

    }

    @Test
    public void testSearchAndBindConfiguration() throws Exception {
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

        ConfigurableEnvironment environment = deserialized.getLdapConfigurationEnvironment();
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
}
