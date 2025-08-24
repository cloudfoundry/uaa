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
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class LdapProviderDefinitionDeserializeTests {
    @Test
    void type_should_be_ldap() {
        String json = """
                {
                  "active": true,
                  "config": {
                    "autoAddGroups": true,
                    "baseUrl": "ldap://test-identity-provider-9bmlg.url",
                    "ldapGroupFile": "ldap/ldap-groups-null.xml",
                    "ldapProfileFile": "ldap/ldap-simple-bind.xml",
                    "skipSSLVerification": true
                  },
                  "name": "test-identity-provider-9bmlg",
                  "originKey": "ldap",
                  "type": "ldap"
                }""";

        IdentityProvider<LdapIdentityProviderDefinition> def = JsonUtils.readValue(json, new TypeReference<IdentityProvider<LdapIdentityProviderDefinition>>() {
        });
        assertThat(def.getType()).isEqualTo(OriginKeys.LDAP);
        assertThat(def.getConfig().getBaseUrl()).isEqualTo("ldap://test-identity-provider-9bmlg.url");
    }

    @Test
    void old_style_type_should_be_ldap() {
        String json = """
                {
                	"active": true,
                	"config": "{\\"autoAddGroups\\": true,\\"baseUrl\\": \\"ldap://test-identity-provider-9bmlg.url\\",\\"ldapGroupFile\\": \\"ldap/ldap-groups-null.xml\\",\\"ldapProfileFile\\": \\"ldap/ldap-simple-bind.xml\\",\\"skipSSLVerification\\": true}",
                	"name": "test-identity-provider-9bmlg",
                	"originKey": "ldap",
                	"type": "ldap"
                }\
                """;
        IdentityProvider<LdapIdentityProviderDefinition> def = JsonUtils.readValue(json, new TypeReference<IdentityProvider<LdapIdentityProviderDefinition>>() {
        });
        assertThat(def.getType()).isEqualTo(OriginKeys.LDAP);
        assertThat(def.getConfig().getBaseUrl()).isEqualTo("ldap://test-identity-provider-9bmlg.url");
    }
}
