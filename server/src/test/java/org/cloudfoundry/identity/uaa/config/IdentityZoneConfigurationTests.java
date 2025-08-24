/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.config;

import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.BrandingInformation;
import org.cloudfoundry.identity.uaa.zone.ClientSecretPolicy;
import org.cloudfoundry.identity.uaa.zone.Consent;
import org.cloudfoundry.identity.uaa.zone.CorsConfiguration;
import org.cloudfoundry.identity.uaa.zone.CorsPolicy;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.Links;
import org.cloudfoundry.identity.uaa.zone.SamlConfig;
import org.cloudfoundry.identity.uaa.zone.TokenPolicy;
import org.cloudfoundry.identity.uaa.zone.UserConfig;
import org.cloudfoundry.identity.uaa.zone.ZoneManagementScopes;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.http.HttpHeaders.ACCEPT;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpHeaders.CONTENT_TYPE;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;

class IdentityZoneConfigurationTests {

    private IdentityZoneConfiguration definition;

    @BeforeEach
    void configure() {
        definition = new IdentityZoneConfiguration();
    }

    @Test
    void default_user_groups_when_json_is_deserialized() {
        definition.setUserConfig(null);
        String s = JsonUtils.writeValueAsString(definition);
        assertThat(s).doesNotContain("userConfig");
        definition = JsonUtils.readValue(s, IdentityZoneConfiguration.class);
        assertThat(definition.getUserConfig()).isNotNull();
        assertThat(definition.getUserConfig().getDefaultGroups()).contains("openid", "password.write", "uaa.user", "approvals.me", "profile", "roles", "user_attributes", "uaa.offline_token");
        assertThat(definition.getUserConfig().resultingAllowedGroups()).isNull();
        s = JsonUtils.writeValueAsString(definition);
        assertThat(s).contains("userConfig")
                .contains("uaa.offline_token");
    }

    @Test
    void deserializeIdentityZoneJSON_withUnknownProperties_doesNotFail() {
        String config = "{ \"unknown-property\": \"unknown-value\"}";
        JsonUtils.readValue(config, IdentityZone.class);
    }

    @Test
    void deserializeJSON_withUnknownProperties_doesNotFail() {
        String config = "{ \"unknown-property\": \"unknown-value\"}";
        JsonUtils.readValue(config, IdentityZoneConfiguration.class);
    }

    @Test
    void deserializeBrandingJSON_withUnknownProperties_doesNotFail() {
        String config = "{ \"unknown-property\": \"unknown-value\"}";
        JsonUtils.readValue(config, BrandingInformation.class);
    }

    @Test
    void deserializeClientSecretPolicyJSON_withUnknownProperties_doesNotFail() {
        String config = "{ \"unknown-property\": \"unknown-value\"}";
        JsonUtils.readValue(config, ClientSecretPolicy.class);
    }

    @Test
    void deserializeLinksJSON_withUnknownProperties_doesNotFail() {
        String config = "{ \"unknown-property\": \"unknown-value\"}";
        JsonUtils.readValue(config, Links.class);
    }

    @Test
    void deserializeConsentJSON_withUnknownProperties_doesNotFail() {
        String config = "{ \"unknown-property\": \"unknown-value\"}";
        JsonUtils.readValue(config, Consent.class);
    }

    @Test
    void deserializeCorsConfigurationJSON_withUnknownProperties_doesNotFail() {
        String config = "{ \"unknown-property\": \"unknown-value\"}";
        JsonUtils.readValue(config, CorsConfiguration.class);
    }

    @Test
    void deserializeCorsPolicyJSON_withUnknownProperties_doesNotFail() {
        String config = "{ \"unknown-property\": \"unknown-value\"}";
        JsonUtils.readValue(config, CorsPolicy.class);
    }

    @Test
    void deserializeSamlConfigJSON_withUnknownProperties_doesNotFail() {
        String config = "{ \"unknown-property\": \"unknown-value\"}";
        JsonUtils.readValue(config, SamlConfig.class);
    }

    @Test
    void deserializeTokenPolicyJSON_withUnknownProperties_doesNotFail() {
        String config = "{ \"unknown-property\": \"unknown-value\"}";
        JsonUtils.readValue(config, TokenPolicy.class);
    }

    @Test
    void deserializeUserConfigJSON_withUnknownProperties_doesNotFail() {
        String config = "{ \"unknown-property\": \"unknown-value\"}";
        JsonUtils.readValue(config, UserConfig.class);
    }

    @Test
    void deserializeZmsJSON_withUnknownProperties_doesNotFail() {
        String config = "{ \"unknown-property\": \"unknown-value\"}";
        JsonUtils.readValue(config, ZoneManagementScopes.class);
    }

    @Test
    void want_assertion_signed_setters() {
        assertThat(definition.getSamlConfig().isRequestSigned()).isTrue();
        definition = JsonUtils.readValue(JsonUtils.writeValueAsString(definition), IdentityZoneConfiguration.class);
        assertThat(definition.getSamlConfig().isRequestSigned()).isTrue();
        definition.getSamlConfig().setRequestSigned(false);
        assertThat(definition.getSamlConfig().isRequestSigned()).isFalse();
    }

    @Test
    void disable_redirect_flag_vestigial() {
        definition.getLinks().getLogout().setDisableRedirectParameter(true);

        assertThat(definition.getLinks().getLogout().isDisableRedirectParameter()).as("setting disableRedirectParameter should not have worked.").isFalse();
    }

    @Test
    void request_signed_setters() {
        assertThat(definition.getSamlConfig().isWantAssertionSigned()).isTrue();
        definition = JsonUtils.readValue(JsonUtils.writeValueAsString(definition), IdentityZoneConfiguration.class);
        assertThat(definition.getSamlConfig().isWantAssertionSigned()).isTrue();
        definition.getSamlConfig().setWantAssertionSigned(false);
        assertThat(definition.getSamlConfig().isWantAssertionSigned()).isFalse();
    }

    @Test
    void deserializeWithoutSamlConfig() {
        String s = JsonUtils.writeValueAsString(definition);
        s = s.replace(",\"samlConfig\":{\"requestSigned\":false,\"wantAssertionSigned\":true}", "");
        definition = JsonUtils.readValue(s, IdentityZoneConfiguration.class);
        assertThat(definition.getSamlConfig().isRequestSigned()).isTrue();
        assertThat(definition.getSamlConfig().isWantAssertionSigned()).isTrue();
        definition.getSamlConfig().setWantAssertionSigned(true);
        definition.getSamlConfig().setRequestSigned(true);
        s = JsonUtils.writeValueAsString(definition);
        definition = JsonUtils.readValue(s, IdentityZoneConfiguration.class);
        assertThat(definition.getSamlConfig().isRequestSigned()).isTrue();
        assertThat(definition.getSamlConfig().isWantAssertionSigned()).isTrue();
        definition.getSamlConfig().setWantAssertionSigned(false);
        definition.getSamlConfig().setRequestSigned(false);
        s = JsonUtils.writeValueAsString(definition);
        definition = JsonUtils.readValue(s, IdentityZoneConfiguration.class);
        assertThat(definition.getSamlConfig().isRequestSigned()).isFalse();
        assertThat(definition.getSamlConfig().isWantAssertionSigned()).isFalse();
    }

    @Test
    void deserializeWithSamlConfig() {
        assertThat(definition.getSamlConfig().isDisableInResponseToCheck()).isFalse();
        String s = JsonUtils.writeValueAsString(definition);
        s = s.replace("\"wantAssertionSigned\":true", "\"wantAssertionSigned\":false");
        s = s.replace("\"disableInResponseToCheck\":false", "\"disableInResponseToCheck\":true");
        definition = JsonUtils.readValue(s, IdentityZoneConfiguration.class);
        assertThat(definition.getSamlConfig().isRequestSigned()).isTrue();
        assertThat(definition.getSamlConfig().isWantAssertionSigned()).isFalse();
        assertThat(definition.getSamlConfig().isDisableInResponseToCheck()).isTrue();
        s = s.replace("\"disableInResponseToCheck\":true,", "");
        s = s.replace(",\"disableInResponseToCheck\":true", "");
        definition = JsonUtils.readValue(s, IdentityZoneConfiguration.class);
        assertThat(definition.getSamlConfig().isDisableInResponseToCheck()).isFalse();
    }

    @Test
    void defaultCorsConfiguration() {
        assertThat(definition.getCorsPolicy().getDefaultConfiguration().getAllowedHeaders()).isEqualTo(Arrays.asList(new String[]{ACCEPT, AUTHORIZATION, CONTENT_TYPE}));
        assertThat(definition.getCorsPolicy().getDefaultConfiguration().getAllowedMethods()).isEqualTo(Collections.singletonList(GET.toString()));
        assertThat(definition.getCorsPolicy().getDefaultConfiguration().getAllowedUris()).isEqualTo(Collections.singletonList(".*"));
        assertThat(definition.getCorsPolicy().getDefaultConfiguration().getAllowedUriPatterns()).isEqualTo(Collections.emptyList());
        assertThat(definition.getCorsPolicy().getDefaultConfiguration().getAllowedOrigins()).isEqualTo(Collections.singletonList(".*"));
        assertThat(definition.getCorsPolicy().getDefaultConfiguration().getAllowedOriginPatterns()).isEqualTo(Collections.emptyList());
        assertThat(definition.getCorsPolicy().getDefaultConfiguration().getMaxAge()).isEqualTo(1728000);
    }

    @Test
    void deserializeDefaultCorsConfiguration() {
        String s = JsonUtils.writeValueAsString(definition);
        s = s.replace("\"allowedHeaders\":" + "[\"%s\",\"%s\",\"%s\"]".formatted(ACCEPT, AUTHORIZATION, CONTENT_TYPE), "\"allowedHeaders\":[\"" + ACCEPT + "\"]");
        s = s.replace("\"allowedMethods\":" + "[\"%s\"]".formatted(GET.toString()), "\"allowedMethods\":" + "[\"%s\",\"%s\"]".formatted(GET.toString(), POST.toString()));
        s = s.replace("\"allowedOrigins\":[\".*\"]", "\"allowedOrigins\":[\"^localhost$\",\"^.*\\\\.localhost$\"]");
        s = s.replace("\"allowedUris\":[\".*\"]", "\"allowedUris\":[\"^/uaa/userinfo$\",\"^/uaa/logout\\\\.do$\"]");
        definition = JsonUtils.readValue(s, IdentityZoneConfiguration.class);

        assertThat(definition.getCorsPolicy().getDefaultConfiguration().getAllowedHeaders()).isEqualTo(Arrays.asList(new String[]{ACCEPT}));
        assertThat(definition.getCorsPolicy().getDefaultConfiguration().getAllowedMethods()).isEqualTo(Arrays.asList(new String[]{GET.toString(), POST.toString()}));
        assertThat(definition.getCorsPolicy().getDefaultConfiguration().getAllowedUris()).isEqualTo(Arrays.asList(new String[]{"^/uaa/userinfo$", "^/uaa/logout\\.do$"}));
        assertThat(definition.getCorsPolicy().getDefaultConfiguration().getAllowedUriPatterns()).isEqualTo(Collections.emptyList());
        assertThat(definition.getCorsPolicy().getDefaultConfiguration().getAllowedOrigins()).isEqualTo(Arrays.asList(new String[]{"^localhost$", "^.*\\.localhost$"}));
        assertThat(definition.getCorsPolicy().getDefaultConfiguration().getAllowedOriginPatterns()).isEqualTo(Collections.emptyList());
        assertThat(definition.getCorsPolicy().getDefaultConfiguration().getMaxAge()).isEqualTo(1728000);
    }

    @Test
    void serializeDefaultIdentityProvider() {
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.setDefaultIdentityProvider("originkey");

        String configString = JsonUtils.writeValueAsString(config);
        assertThat(configString).contains("\"defaultIdentityProvider\"")
                .contains("\"originkey\"");

        IdentityZoneConfiguration deserializedConfig = JsonUtils.readValue(configString, IdentityZoneConfiguration.class);
        assertThat(deserializedConfig.getDefaultIdentityProvider()).isEqualTo(config.getDefaultIdentityProvider());
    }
}
