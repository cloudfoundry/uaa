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

import org.cloudfoundry.identity.uaa.login.Prompt;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.jupiter.api.Test;

import java.net.MalformedURLException;
import java.net.URI;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class OIDCIdentityProviderDefinitionTests {

    private final String defaultJson = "{\"emailDomain\":null,\"additionalConfiguration\":null,\"providerDescription\":null,\"externalGroupsWhitelist\":[],\"attributeMappings\":{},\"addShadowUserOnLogin\":true,\"storeCustomAttributes\":false,\"authUrl\":null,\"tokenUrl\":null,\"tokenKeyUrl\":null,\"tokenKey\":null,\"linkText\":null,\"showLinkText\":true,\"skipSslValidation\":false,\"tokenExchangeEnabled\":true,\"relyingPartyId\":null,\"relyingPartySecret\":null,\"scopes\":null,\"issuer\":null,\"responseType\":\"code\",\"userInfoUrl\":null,\"jwtClientAuthentication\":false,\"additionalAuthzParameters\":{\"token_format\":\"jwt\"}}";
    String url = "https://accounts.google.com/.well-known/openid-configuration";

    @Test
    void serialize_discovery_url() throws MalformedURLException {
        OIDCIdentityProviderDefinition def = JsonUtils.readValue(defaultJson, OIDCIdentityProviderDefinition.class);
        assertThat(def.getDiscoveryUrl()).isNull();
        def.setDiscoveryUrl(URI.create(url).toURL());
        assertThat(def.getDiscoveryUrl()).hasToString(url);
        String json = JsonUtils.writeValueAsString(def);
        def = JsonUtils.readValue(json, OIDCIdentityProviderDefinition.class);
        assertThat(def.getDiscoveryUrl()).hasToString(url);
        assertThat(def.getAdditionalAuthzParameters()).containsEntry("token_format", "jwt");
    }

    @Test
    void serializableObjectCalls() throws CloneNotSupportedException {
        OIDCIdentityProviderDefinition def = JsonUtils.readValue(defaultJson, OIDCIdentityProviderDefinition.class);
        OIDCIdentityProviderDefinition def2 = (OIDCIdentityProviderDefinition) def.clone();
        assertThat(def2).isEqualTo(def)
                .hasSameHashCodeAs(def);
        assertThat(def2.getAdditionalAuthzParameters()).hasSize(1)
                .containsEntry("token_format", "jwt");
    }

    @Test
    void serialize_prompts() {
        OIDCIdentityProviderDefinition def = JsonUtils.readValue(defaultJson, OIDCIdentityProviderDefinition.class);
        assertThat(def.getPrompts()).isNull();
        List<Prompt> prompts = Arrays.asList(new Prompt("username", "text", "Email"),
                new Prompt("password", "password", "Password"),
                new Prompt("passcode", "password", "Temporary Authentication Code (Get on at /passcode)"));
        def.setPrompts(prompts);
        String json = JsonUtils.writeValueAsString(def);
        def = JsonUtils.readValue(json, OIDCIdentityProviderDefinition.class);
        assertThat(def.getPrompts()).isEqualTo(prompts);
    }

    @Test
    void equalsTests() throws CloneNotSupportedException {
        OIDCIdentityProviderDefinition original = JsonUtils.readValue(defaultJson, OIDCIdentityProviderDefinition.class);
        OIDCIdentityProviderDefinition compare = (OIDCIdentityProviderDefinition) original.clone();
        compare.setTokenExchangeEnabled(false);
        assertThat(original).isNotEqualTo(compare);
    }

    @Test
    void serialize_jwtClientAuthentication() {
        OIDCIdentityProviderDefinition def = JsonUtils.readValue(defaultJson, OIDCIdentityProviderDefinition.class);
        assertThat(def.getPrompts()).isNull();
        Map<String, String> settings = new HashMap<>();
        settings.put("iss", "issuer");
        def.setJwtClientAuthentication(settings);
        String json = JsonUtils.writeValueAsString(def);
        def = JsonUtils.readValue(json, OIDCIdentityProviderDefinition.class);
        assertThat(def.getJwtClientAuthentication()).isEqualTo(settings);
        assertThat(def.getAuthMethod()).isNull();
    }
}
