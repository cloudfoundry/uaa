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
        compare.setOmitIdTokenHintOnLogout(false);
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

    @Test
    void testToString() throws MalformedURLException {
        OIDCIdentityProviderDefinition def = new OIDCIdentityProviderDefinition();
        def.setDiscoveryUrl(URI.create(url).toURL());
        def.setPasswordGrantEnabled(true);
        def.setSetForwardHeader(true);
        def.setTokenExchangeEnabled(true);
        def.setOmitIdTokenHintOnLogout(true);

        List<Prompt> prompts = Arrays.asList(
            new Prompt("username", "text", "Email"),
            new Prompt("password", "password", "Password")
        );
        def.setPrompts(prompts);

        Map<String, String> jwtSettings = new HashMap<>();
        jwtSettings.put("iss", "issuer");
        def.setJwtClientAuthentication(jwtSettings);

        Map<String, String> authzParams = new HashMap<>();
        authzParams.put("token_format", "jwt");
        def.setAdditionalAuthzParameters(authzParams);

        String result = def.toString();

        // Verify all attributes are present in toString output
        assertThat(result).contains("OIDCIdentityProviderDefinition{")
        .contains("discoveryUrl=" + def.getDiscoveryUrl())
        .contains("passwordGrantEnabled=true")
        .contains("setForwardHeader=true")
        .contains("tokenExchangeEnabled=true")
        .contains("omitIdTokenHintOnLogout=true")
        .contains("prompts=")
        .contains("jwtClientAuthentication=")
        .contains("additionalAuthzParameters=")
        .contains("parent=");
    }

    @Test
    void testToStringWithNullValues() {
        OIDCIdentityProviderDefinition def = new OIDCIdentityProviderDefinition();

        String result = def.toString();

        // Verify toString works with null values
        assertThat(result).contains("OIDCIdentityProviderDefinition{")
        .contains("discoveryUrl=null")
        .contains("passwordGrantEnabled=false")
        .contains("setForwardHeader=false")
        .contains("tokenExchangeEnabled=null")
        .contains("omitIdTokenHintOnLogout=null")
        .contains("prompts=null")
        .contains("jwtClientAuthentication=null")
        .contains("additionalAuthzParameters=null");
    }
}
