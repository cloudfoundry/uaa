/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
 *
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.provider;

import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.Test;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Collections;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;


public class OIDCIdentityProviderDefinitionTests {

    private final String defaultJson = "{\"emailDomain\":null,\"additionalConfiguration\":null,\"providerDescription\":null,\"externalGroupsWhitelist\":[],\"attributeMappings\":{},\"addShadowUserOnLogin\":true,\"storeCustomAttributes\":false,\"authUrl\":null,\"tokenUrl\":null,\"tokenKeyUrl\":null,\"tokenKey\":null,\"linkText\":null,\"showLinkText\":true,\"skipSslValidation\":false,\"relyingPartyId\":null,\"relyingPartySecret\":null,\"scopes\":null,\"issuer\":null,\"responseType\":\"code\",\"userInfoUrl\":null}";
    String url = "https://accounts.google.com/.well-known/openid-configuration";

    @Test
    public void serialize_discovery_url() throws MalformedURLException {
        OIDCIdentityProviderDefinition def = JsonUtils.readValue(defaultJson, OIDCIdentityProviderDefinition.class);
        assertNull(def.getDiscoveryUrl());
        def.setDiscoveryUrl(new URL(url));
        assertEquals(url, def.getDiscoveryUrl().toString());
        String json = JsonUtils.writeValueAsString(def);
        def = JsonUtils.readValue(json, OIDCIdentityProviderDefinition.class);
        assertEquals(url, def.getDiscoveryUrl().toString());
    }

    @Test
    public void serialize_relying_party_grant_types() {
        String jsonValue = "{\"relyingPartyGrantTypes\":[\"password\",\"authorization_code\",\"implicit\"]}";

        OIDCIdentityProviderDefinition providerDefinition = JsonUtils.readValue(jsonValue, OIDCIdentityProviderDefinition.class);
        assertNotNull(providerDefinition);
        assertNotNull(providerDefinition.getRelyingPartyGrantTypes());
        assertEquals(3, providerDefinition.getRelyingPartyGrantTypes().size());
        assertTrue(providerDefinition.getRelyingPartyGrantTypes().contains(OIDCIdentityProviderDefinition.OIDCGrantType.password));
        assertTrue(providerDefinition.getRelyingPartyGrantTypes().contains(OIDCIdentityProviderDefinition.OIDCGrantType.authorization_code));
        assertTrue(providerDefinition.getRelyingPartyGrantTypes().contains(OIDCIdentityProviderDefinition.OIDCGrantType.implicit));

        providerDefinition.setRelyingPartyGrantTypes(Collections.singletonList(OIDCIdentityProviderDefinition.OIDCGrantType.password));

        String valueAsString = JsonUtils.writeValueAsString(providerDefinition);

        assertThat(valueAsString, containsString("password"));
        assertThat(valueAsString, not(containsString("implicit")));
    }

    @Test
    public void serialize_invalid_relying_party_grant_types() {
        String invalidJsonValue = "{\"relyingPartyGrantTypes\":[\"password\",\"authorization_code\",\"implicit\",\"client_credentials\"]}";
        try {
            JsonUtils.readValue(invalidJsonValue, OIDCIdentityProviderDefinition.class);
            fail();
        } catch (JsonUtils.JsonUtilException e) {
            //NOTHING
        }
    }

    @Test
    public void clone_relying_party_grant_types() throws CloneNotSupportedException {
        String jsonValue = "{\"relyingPartyGrantTypes\":[\"password\",\"authorization_code\",\"implicit\"]}";
        OIDCIdentityProviderDefinition providerDefinition = JsonUtils.readValue(jsonValue, OIDCIdentityProviderDefinition.class);

        assertNotNull(providerDefinition);
        Object clone = providerDefinition.clone();
        assertTrue(clone instanceof OIDCIdentityProviderDefinition);
        OIDCIdentityProviderDefinition cloneDefinition = (OIDCIdentityProviderDefinition)clone;


        assertNotNull(cloneDefinition.getRelyingPartyGrantTypes());
        assertEquals(3, cloneDefinition.getRelyingPartyGrantTypes().size());
        assertTrue(cloneDefinition.getRelyingPartyGrantTypes().contains(OIDCIdentityProviderDefinition.OIDCGrantType.password));
        assertTrue(cloneDefinition.getRelyingPartyGrantTypes().contains(OIDCIdentityProviderDefinition.OIDCGrantType.authorization_code));
        assertTrue(cloneDefinition.getRelyingPartyGrantTypes().contains(OIDCIdentityProviderDefinition.OIDCGrantType.implicit));
    }
}