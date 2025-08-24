/*
 * ******************************************************************************
 *  *     Cloud Foundry
 *  *     Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *  *
 *  *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *  *     You may not use this product except in compliance with the License.
 *  *
 *  *     This product includes a number of subcomponents with
 *  *     separate copyright notices and license terms. Your use of these
 *  *     subcomponents is subject to the terms and conditions of the
 *  *     subcomponent's license, as noted in the LICENSE file.
 *  ******************************************************************************
 */

package org.cloudfoundry.identity.uaa.authentication;

import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class UaaAuthenticationSerializationTests {

    private static final String COST_CENTER = "costCenter";
    private static final String DENVER_CO = "Denver,CO";
    private static final String MANAGER = "manager";
    private static final String JOHN_THE_SLOTH = "John the Sloth";
    private static final String KARI_THE_ANT_EATER = "Kari the Ant Eater";

    @Test
    void serialization() {
        UaaPrincipal principal = new UaaPrincipal("id", "username", "email", "origin", "externalId", "zoneId");
        HttpSession session = mock(HttpSession.class);
        when(session.getId()).thenReturn("id");
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRemoteAddr()).thenReturn("remoteAddr");
        when(request.getSession(false)).thenReturn(session);
        when(request.getContextPath()).thenReturn("");
        when(request.getRequestURI()).thenReturn("");
        UaaAuthenticationDetails details = new UaaAuthenticationDetails(request, "clientId");
        details.setAddNew(true);

        List<? extends GrantedAuthority> authorities = Arrays.asList(new SimpleGrantedAuthority("role1"), new SimpleGrantedAuthority("role2"));
        String credentials = "credentials";
        Map<String, List<String>> userAttributes = new HashMap<>();
        userAttributes.put("atest", Arrays.asList("test1", "test2", "test3"));
        userAttributes.put("btest", Arrays.asList("test1", "test2", "test3"));
        Set<String> externalGroups = new HashSet<>(Arrays.asList("group1", "group2", "group3"));

        boolean authenticated = true;
        long authenticatedTime = System.currentTimeMillis();
        long expiresAt = Long.MAX_VALUE;

        UaaAuthentication expected = new UaaAuthentication(principal, credentials, authorities, externalGroups, userAttributes, details, authenticated, authenticatedTime, expiresAt);
        String authenticationAsJson = JsonUtils.writeValueAsString(expected);
        UaaAuthentication actual = JsonUtils.readValue(authenticationAsJson, UaaAuthentication.class);

        //validate authentication details
        UaaAuthenticationDetails actualDetails = actual.getUaaAuthenticationDetails();
        assertThat(actualDetails).isNotNull().isSameAs(actual.getDetails());
        assertThat(actualDetails.getOrigin()).isEqualTo("remoteAddr");
        assertThat(actualDetails.getSessionId()).isEqualTo("id");
        assertThat(actualDetails.getClientId()).isEqualTo("clientId");
        assertThat(actualDetails.isAddNew()).isTrue();

        //validate principal
        UaaPrincipal actualPrincipal = actual.getPrincipal();
        assertThat(actualPrincipal.getId()).isEqualTo("id");
        assertThat(actualPrincipal.getName()).isEqualTo("username");
        assertThat(actualPrincipal.getEmail()).isEqualTo("email");
        assertThat(actualPrincipal.getOrigin()).isEqualTo("origin");
        assertThat(actualPrincipal.getExternalId()).isEqualTo("externalId");
        assertThat(actualPrincipal.getZoneId()).isEqualTo("zoneId");

        //validate authorities
        assertThat(actual.getAuthorities()).contains(new SimpleGrantedAuthority("role1"), new SimpleGrantedAuthority("role2"));

        //validate external groups
        assertThat(actual.getExternalGroups()).contains("group1", "group2", "group3");

        //validate user attributes
        assertThat(actual.getUserAttributes()).hasSize(2);
        assertThat(actual.getUserAttributes().get("atest")).contains("test1", "test2", "test3");
        assertThat(actual.getUserAttributes().get("btest")).contains("test1", "test2", "test3");

        //validate authenticated
        assertThat(actual.isAuthenticated()).isEqualTo(authenticated);

        //validate authenticated time
        assertThat(actual.getAuthenticatedTime()).isEqualTo(authenticatedTime);

        //validate expires at time
        assertThat(actual.getExpiresAt()).isEqualTo(expiresAt);
    }

    @Test
    void deserializationWithoutAuthenticatedTime() {
        String data = "{\"principal\":{\"id\":\"user-id\",\"name\":\"username\",\"email\":\"email\",\"origin\":\"uaa\",\"externalId\":null,\"zoneId\":\"uaa\"},\"credentials\":null,\"authorities\":[],\"details\":null,\"authenticated\":true,\"authenticatedTime\":1438649464353,\"name\":\"username\"}";
        UaaAuthentication authentication1 = JsonUtils.readValue(data, UaaAuthentication.class);
        assertThat(authentication1.getAuthenticatedTime()).isEqualTo(1438649464353L);
        assertThat(authentication1.getExpiresAt()).isEqualTo(-1);
        assertThat(authentication1.isAuthenticated()).isTrue();
        assertThat(authentication1.getAuthContextClassRef()).isNull();
        String dataWithoutTime = "{\"principal\":{\"id\":\"user-id\",\"name\":\"username\",\"email\":\"email\",\"origin\":\"uaa\",\"externalId\":null,\"zoneId\":\"uaa\"},\"credentials\":null,\"authorities\":[],\"details\":null,\"authenticated\":true,\"name\":\"username\"}";
        UaaAuthentication authentication2 = JsonUtils.readValue(dataWithoutTime, UaaAuthentication.class);
        assertThat(authentication2.getAuthenticatedTime()).isEqualTo(-1);

        long inThePast = System.currentTimeMillis() - 1000L * 60L;
        data = "{\"principal\":{\"id\":\"user-id\",\"name\":\"username\",\"email\":\"email\",\"origin\":\"uaa\",\"externalId\":null,\"zoneId\":\"uaa\"},\"credentials\":null,\"authorities\":[],\"details\":null,\"authenticated\":true,\"authenticatedTime\":1438649464353,\"name\":\"username\", \"expiresAt\":" + inThePast + "}";
        UaaAuthentication authentication3 = JsonUtils.readValue(data, UaaAuthentication.class);
        assertThat(authentication3.getAuthenticatedTime()).isEqualTo(1438649464353L);
        assertThat(authentication3.getExpiresAt()).isEqualTo(inThePast);
        assertThat(authentication3.isAuthenticated()).isFalse();

        long inTheFuture = System.currentTimeMillis() + 1000L * 60L;
        data = "{\"principal\":{\"id\":\"user-id\",\"name\":\"username\",\"email\":\"email\",\"origin\":\"uaa\",\"externalId\":null,\"zoneId\":\"uaa\"},\"credentials\":null,\"authorities\":[],\"details\":null,\"authenticated\":true,\"authenticatedTime\":1438649464353,\"name\":\"username\", \"expiresAt\":" + inTheFuture + "}";
        UaaAuthentication authentication4 = JsonUtils.readValue(data, UaaAuthentication.class);
        assertThat(authentication4.getAuthenticatedTime()).isEqualTo(1438649464353L);
        assertThat(authentication4.getExpiresAt()).isEqualTo(inTheFuture);
        assertThat(authentication4.isAuthenticated()).isTrue();
    }

    @Test
    void deserialization_with_external_groups() {
        String dataWithExternalGroups = "{\"principal\":{\"id\":\"user-id\",\"name\":\"username\",\"email\":\"email\",\"origin\":\"uaa\",\"externalId\":null,\"zoneId\":\"uaa\"},\"credentials\":null,\"authorities\":[],\"externalGroups\":[\"something\",\"or\",\"other\",\"something\"],\"details\":null,\"authenticated\":true,\"authenticatedTime\":null,\"name\":\"username\"}";
        UaaAuthentication authentication = JsonUtils.readValue(dataWithExternalGroups, UaaAuthentication.class);
        assertThat(authentication.getExternalGroups())
                .hasSize(3)
                .contains("something", "or", "other");
        assertThat(authentication.isAuthenticated()).isTrue();
    }

    @Test
    void deserialization_with_user_attributes() {
        String dataWithoutUserAttributes = "{\"principal\":{\"id\":\"user-id\",\"name\":\"username\",\"email\":\"email\",\"origin\":\"uaa\",\"externalId\":null,\"zoneId\":\"uaa\"},\"credentials\":null,\"authorities\":[],\"externalGroups\":[\"something\",\"or\",\"other\",\"something\"],\"details\":null,\"authenticated\":true,\"authenticatedTime\":null,\"name\":\"username\", \"previousLoginSuccessTime\":1485305759347}";
        UaaAuthentication authentication = JsonUtils.readValue(dataWithoutUserAttributes, UaaAuthentication.class);
        assertThat(authentication.getExternalGroups())
                .hasSize(3)
                .contains("something", "or", "other");
        assertThat(authentication.isAuthenticated()).isTrue();

        MultiValueMap<String, String> userAttributes = new LinkedMultiValueMap<>();
        userAttributes.add(COST_CENTER, DENVER_CO);
        userAttributes.add(MANAGER, JOHN_THE_SLOTH);
        userAttributes.add(MANAGER, KARI_THE_ANT_EATER);
        authentication.setUserAttributes(userAttributes);

        String dataWithUserAttributes = JsonUtils.writeValueAsString(authentication);
        assertThat(dataWithUserAttributes).as("userAttributes should be part of the JSON").contains("userAttributes");

        UaaAuthentication authWithUserData = JsonUtils.readValue(dataWithUserAttributes, UaaAuthentication.class);
        assertThat(authWithUserData.getUserAttributes()).isNotNull();
        assertThat(authWithUserData.getUserAttributes().entrySet()).containsExactlyInAnyOrderElementsOf(userAttributes.entrySet());
        assertThat(userAttributes.entrySet()).containsExactlyInAnyOrderElementsOf(authWithUserData.getUserAttributes().entrySet());

        assertThat(authentication.getExternalGroups())
                .hasSize(3)
                .contains("something", "or", "other");
        assertThat(authentication.isAuthenticated()).isTrue();
        assertThat(authentication.getLastLoginSuccessTime()).isEqualTo((Long) 1485305759347L);
    }
}
