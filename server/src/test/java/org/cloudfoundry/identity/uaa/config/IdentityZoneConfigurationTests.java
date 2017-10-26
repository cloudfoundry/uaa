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
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.junit.Before;
import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;

import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.springframework.http.HttpHeaders.ACCEPT;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpHeaders.CONTENT_TYPE;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;

public class IdentityZoneConfigurationTests {

    private IdentityZoneConfiguration definition;
    @Before
    public void configure() {
        definition = new IdentityZoneConfiguration();
    }

    @Test
    public void default_user_groups_when_json_is_deserialized() throws Exception {
        definition.setUserConfig(null);
        String s = JsonUtils.writeValueAsString(definition);
        assertThat(s, not(containsString("userConfig")));
        definition = JsonUtils.readValue(s, IdentityZoneConfiguration.class);
        assertNotNull(definition.getUserConfig());
        assertThat(definition.getUserConfig().getDefaultGroups(), containsInAnyOrder(
            "openid",
            "password.write",
            "uaa.user",
            "approvals.me",
            "profile",
            "roles",
            "user_attributes",
            "uaa.offline_token"
        ));
        s = JsonUtils.writeValueAsString(definition);
        assertThat(s, containsString("userConfig"));
        assertThat(s, containsString("uaa.offline_token"));
    }

    @Test
    public void test_want_assertion_signed_setters() {
        assertTrue(definition.getSamlConfig().isRequestSigned());
        definition = JsonUtils.readValue(JsonUtils.writeValueAsString(definition), IdentityZoneConfiguration.class);
        assertTrue(definition.getSamlConfig().isRequestSigned());
        definition.getSamlConfig().setRequestSigned(false);
        assertFalse(definition.getSamlConfig().isRequestSigned());
    }

    @Test
    public void test_disable_redirect_flag_vestigial() {
        definition.getLinks().getLogout().setDisableRedirectParameter(true);

        assertFalse("setting disableRedirectParameter should not have worked.", definition.getLinks().getLogout().isDisableRedirectParameter());
    }

    @Test
    public void test_request_signed_setters() {
        assertTrue(definition.getSamlConfig().isWantAssertionSigned());
        definition = JsonUtils.readValue(JsonUtils.writeValueAsString(definition), IdentityZoneConfiguration.class);
        assertTrue(definition.getSamlConfig().isWantAssertionSigned());
        definition.getSamlConfig().setWantAssertionSigned(false);
        assertFalse(definition.getSamlConfig().isWantAssertionSigned());
    }

    @Test
    public void testDeserialize_Without_SamlConfig() {
        String s = JsonUtils.writeValueAsString(definition);
        s = s.replace(",\"samlConfig\":{\"requestSigned\":false,\"wantAssertionSigned\":true}","");
        definition = JsonUtils.readValue(s, IdentityZoneConfiguration.class);
        assertTrue(definition.getSamlConfig().isRequestSigned());
        assertTrue(definition.getSamlConfig().isWantAssertionSigned());
        definition.getSamlConfig().setWantAssertionSigned(true);
        definition.getSamlConfig().setRequestSigned(true);
        s = JsonUtils.writeValueAsString(definition);
        definition = JsonUtils.readValue(s, IdentityZoneConfiguration.class);
        assertTrue(definition.getSamlConfig().isRequestSigned());
        assertTrue(definition.getSamlConfig().isWantAssertionSigned());
        definition.getSamlConfig().setWantAssertionSigned(false);
        definition.getSamlConfig().setRequestSigned(false);
        s = JsonUtils.writeValueAsString(definition);
        definition = JsonUtils.readValue(s, IdentityZoneConfiguration.class);
        assertFalse(definition.getSamlConfig().isRequestSigned());
        assertFalse(definition.getSamlConfig().isWantAssertionSigned());
    }

    @Test
    public void testDeserialize_With_SamlConfig() {
        assertFalse(definition.getSamlConfig().isDisableInResponseToCheck());
        String s = JsonUtils.writeValueAsString(definition);
        s = s.replace("\"wantAssertionSigned\":true","\"wantAssertionSigned\":false");
        s = s.replace("\"disableInResponseToCheck\":false","\"disableInResponseToCheck\":true");
        definition = JsonUtils.readValue(s, IdentityZoneConfiguration.class);
        assertTrue(definition.getSamlConfig().isRequestSigned());
        assertFalse(definition.getSamlConfig().isWantAssertionSigned());
        assertTrue(definition.getSamlConfig().isDisableInResponseToCheck());
        s = s.replace("\"disableInResponseToCheck\":true,","");
        s = s.replace(",\"disableInResponseToCheck\":true","");
        definition = JsonUtils.readValue(s, IdentityZoneConfiguration.class);
        assertFalse(definition.getSamlConfig().isDisableInResponseToCheck());
    }

    @Test
    public void testDefaultCorsConfiguration() {
        assertEquals(Arrays.asList(new String[] {ACCEPT, AUTHORIZATION, CONTENT_TYPE}), definition.getCorsPolicy().getDefaultConfiguration().getAllowedHeaders());
        assertEquals(Arrays.asList(GET.toString()), definition.getCorsPolicy().getDefaultConfiguration().getAllowedMethods());
        assertEquals(Arrays.asList(".*"), definition.getCorsPolicy().getDefaultConfiguration().getAllowedUris());
        assertEquals(Collections.EMPTY_LIST, definition.getCorsPolicy().getDefaultConfiguration().getAllowedUriPatterns());
        assertEquals(Arrays.asList(".*"), definition.getCorsPolicy().getDefaultConfiguration().getAllowedOrigins());
        assertEquals(Collections.EMPTY_LIST, definition.getCorsPolicy().getDefaultConfiguration().getAllowedOriginPatterns());
        assertEquals(1728000, definition.getCorsPolicy().getDefaultConfiguration().getMaxAge());
    }

    @Test
    public void testDeserialize_DefaultCorsConfiguration() {
        String s = JsonUtils.writeValueAsString(definition);
        s = s.replace("\"allowedHeaders\":"+String.format("[\"%s\",\"%s\",\"%s\"]", ACCEPT, AUTHORIZATION, CONTENT_TYPE), "\"allowedHeaders\":[\"" + ACCEPT +"\"]" );
        s = s.replace("\"allowedMethods\":"+String.format("[\"%s\"]", GET.toString()), "\"allowedMethods\":" +String.format("[\"%s\",\"%s\"]",GET.toString(), POST.toString()));
        s = s.replace("\"allowedOrigins\":[\".*\"]", "\"allowedOrigins\":[\"^localhost$\",\"^.*\\\\.localhost$\"]" );
        s = s.replace("\"allowedUris\":[\".*\"]", "\"allowedUris\":[\"^/uaa/userinfo$\",\"^/uaa/logout\\\\.do$\"]");
        definition = JsonUtils.readValue(s, IdentityZoneConfiguration.class);

        assertEquals(Arrays.asList(new String[] {ACCEPT}), definition.getCorsPolicy().getDefaultConfiguration().getAllowedHeaders());
        assertEquals(Arrays.asList(new String[] {GET.toString(), POST.toString()}), definition.getCorsPolicy().getDefaultConfiguration().getAllowedMethods());
        assertEquals(Arrays.asList(new String[] {"^/uaa/userinfo$", "^/uaa/logout\\.do$"}), definition.getCorsPolicy().getDefaultConfiguration().getAllowedUris());
        assertEquals(Collections.EMPTY_LIST, definition.getCorsPolicy().getDefaultConfiguration().getAllowedUriPatterns());
        assertEquals(Arrays.asList(new String[] {"^localhost$", "^.*\\.localhost$"}), definition.getCorsPolicy().getDefaultConfiguration().getAllowedOrigins());
        assertEquals(Collections.EMPTY_LIST, definition.getCorsPolicy().getDefaultConfiguration().getAllowedOriginPatterns());
        assertEquals(1728000, definition.getCorsPolicy().getDefaultConfiguration().getMaxAge());
    }
}
