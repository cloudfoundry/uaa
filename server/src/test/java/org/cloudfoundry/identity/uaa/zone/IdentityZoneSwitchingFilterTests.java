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

package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.oauth.UaaOauth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Request;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Collections;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class IdentityZoneSwitchingFilterTests {

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void stripPrefix() {
        String zoneId = new RandomValueStringGenerator().generate();
        IdentityZoneSwitchingFilter filter = new IdentityZoneSwitchingFilter(mock(IdentityZoneProvisioning.class));
        assertThat(filter.stripPrefix("zones." + zoneId + ".admin", zoneId)).isEqualTo("zones." + zoneId + ".admin");
        assertThat(filter.stripPrefix("zones." + zoneId + ".read", zoneId)).isEqualTo("zones." + zoneId + ".read");
        assertThat(filter.stripPrefix("zones." + zoneId + ".clients.admin", zoneId)).isEqualTo("clients.admin");
        assertThat(filter.stripPrefix("zones." + zoneId + ".clients.read", zoneId)).isEqualTo("clients.read");
        assertThat(filter.stripPrefix("zones." + zoneId + ".idps.read", zoneId)).isEqualTo("idps.read");
    }

    @Test
    void getAuthenticationForZone() {
        // Setup
        OAuth2Request oAuth2Request = new OAuth2Request(Map.of("client_id", "id"), "id", Collections.emptyList(), true, Set.of("client"),
                Set.of(), null, null, Map.of("extra", "param"));
        IdentityZoneSwitchingFilter filter = new IdentityZoneSwitchingFilter(mock(IdentityZoneProvisioning.class));
        UaaOauth2Authentication uaaAauth2Authentication = mock(UaaOauth2Authentication.class);
        OAuth2Authentication oAuth2Authentication = mock(OAuth2Authentication.class);
        when(uaaAauth2Authentication.getOAuth2Request()).thenReturn(oAuth2Request);
        when(oAuth2Authentication.getOAuth2Request()).thenReturn(oAuth2Request);
        // When
        SecurityContextHolder.getContext().setAuthentication(uaaAauth2Authentication);
        // Then
        assertThat(filter.getAuthenticationForZone("uaa", new MockHttpServletRequest())).isInstanceOf(UaaOauth2Authentication.class);
        // When
        SecurityContextHolder.getContext().setAuthentication(oAuth2Authentication);
        // Then
        assertThat(filter.getAuthenticationForZone("uaa", new MockHttpServletRequest())).isInstanceOf(OAuth2Authentication.class);
    }
}