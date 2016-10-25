/*
 * ****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
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

package org.cloudfoundry.identity.uaa.mock.ldap;


import com.fasterxml.jackson.core.type.TypeReference;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class LdapProviderDefinitionDeserializeTests {
    @Test
    public void type_should_be_ldap() {
        String json = "{\n" +
            "  \"active\": true,\n" +
            "  \"config\": {\n" +
            "    \"autoAddGroups\": true,\n" +
            "    \"baseUrl\": \"ldap://test-identity-provider-9bmlg.url\",\n" +
            "    \"ldapGroupFile\": \"ldap/ldap-groups-null.xml\",\n" +
            "    \"ldapProfileFile\": \"ldap/ldap-simple-bind.xml\",\n" +
            "    \"skipSSLVerification\": true\n" +
            "  },\n" +
            "  \"name\": \"test-identity-provider-9bmlg\",\n" +
            "  \"originKey\": \"ldap\",\n" +
            "  \"type\": \"ldap\"\n" +
            "}";
        IdentityProvider<LdapIdentityProviderDefinition> def = JsonUtils.readValue(json, new TypeReference<IdentityProvider<LdapIdentityProviderDefinition>>() {});
        assertEquals(OriginKeys.LDAP, def.getType());
        assertEquals("ldap://test-identity-provider-9bmlg.url",def.getConfig().getBaseUrl());
    }

    @Test
    public void old_style_type_should_be_ldap() {
        String json = "{\n" +
            "\t\"active\": true,\n" +
            "\t\"config\": \"{\\\"autoAddGroups\\\": true,\\\"baseUrl\\\": \\\"ldap://test-identity-provider-9bmlg.url\\\",\\\"ldapGroupFile\\\": \\\"ldap/ldap-groups-null.xml\\\",\\\"ldapProfileFile\\\": \\\"ldap/ldap-simple-bind.xml\\\",\\\"skipSSLVerification\\\": true}\",\n" +
            "\t\"name\": \"test-identity-provider-9bmlg\",\n" +
            "\t\"originKey\": \"ldap\",\n" +
            "\t\"type\": \"ldap\"\n" +
            "}";
        IdentityProvider<LdapIdentityProviderDefinition> def = JsonUtils.readValue(json, new TypeReference<IdentityProvider<LdapIdentityProviderDefinition>>() {});
        assertEquals(OriginKeys.LDAP, def.getType());
        assertEquals("ldap://test-identity-provider-9bmlg.url",def.getConfig().getBaseUrl());
    }

}
