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
import org.hamcrest.Matchers;
import org.junit.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.everyItem;
import static org.hamcrest.Matchers.isIn;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class UaaAuthenticationSerializationTests {

    public static final String COST_CENTER = "costCenter";
    public static final String DENVER_CO = "Denver,CO";
    public static final String MANAGER = "manager";
    public static final String JOHN_THE_SLOTH = "John the Sloth";
    public static final String KARI_THE_ANT_EATER = "Kari the Ant Eater";

    @Test
    public void test_serialization() {
        UaaPrincipal principal = new UaaPrincipal("id","username","email","origin","externalId","zoneId");
        HttpSession session = mock(HttpSession.class);
        when(session.getId()).thenReturn("id");
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRemoteAddr()).thenReturn("remoteAddr");
        when(request.getSession(false)).thenReturn(session);
        UaaAuthenticationDetails details = new UaaAuthenticationDetails(request, "clientId");
        details.setAddNew(true);

        List<? extends GrantedAuthority> authorities = Arrays.asList(new SimpleGrantedAuthority("role1"), new SimpleGrantedAuthority("role2"));
        String credentials = "credentials";
        Map<String,List<String>> userAttributes = new HashMap<>();
        userAttributes.put("atest", Arrays.asList("test1","test2","test3"));
        userAttributes.put("btest", Arrays.asList("test1", "test2", "test3"));
        Set<String> externalGroups = new HashSet<>(Arrays.asList("group1","group2","group3"));

        boolean authenticated = true;
        long authenticatedTime = System.currentTimeMillis();
        long expiresAt = Long.MAX_VALUE;

        UaaAuthentication expected = new UaaAuthentication(principal,credentials, authorities, externalGroups,userAttributes, details, authenticated, authenticatedTime, expiresAt);
        String authenticationAsJson = JsonUtils.writeValueAsString(expected);
        UaaAuthentication actual = JsonUtils.readValue(authenticationAsJson, UaaAuthentication.class);

        //validate authentication details
        UaaAuthenticationDetails actualDetails = (UaaAuthenticationDetails)actual.getDetails();
        assertNotNull(actualDetails);
        assertEquals("remoteAddr", actualDetails.getOrigin());
        assertEquals("id", actualDetails.getSessionId());
        assertEquals("clientId", actualDetails.getClientId());
        assertTrue(actualDetails.isAddNew());

        //validate principal
        UaaPrincipal actualPrincipal = actual.getPrincipal();
        assertEquals("id",actualPrincipal.getId());
        assertEquals("username",actualPrincipal.getName());
        assertEquals("email",actualPrincipal.getEmail());
        assertEquals("origin",actualPrincipal.getOrigin());
        assertEquals("externalId",actualPrincipal.getExternalId());
        assertEquals("zoneId", actualPrincipal.getZoneId());

        //validate authorities
        assertThat(actual.getAuthorities(), containsInAnyOrder(new SimpleGrantedAuthority("role1"), new SimpleGrantedAuthority("role2")));

        //validate external groups
        assertThat(actual.getExternalGroups(), containsInAnyOrder("group1","group2","group3"));

        //validate user attributes
        assertEquals(2, actual.getUserAttributes().size());
        assertThat(actual.getUserAttributes().get("atest"),containsInAnyOrder("test1","test2","test3"));
        assertThat(actual.getUserAttributes().get("btest"),containsInAnyOrder("test1","test2","test3"));

        //validate authenticated
        assertEquals(authenticated, actual.isAuthenticated());

        //validate authenticated time
        assertEquals(authenticatedTime, actual.getAuthenticatedTime());

        //validate expires at time
        assertEquals(expiresAt, actual.getExpiresAt());

    }

    @Test
    public void testDeserializationWithoutAuthenticatedTime() {
        String data ="{\"principal\":{\"id\":\"user-id\",\"name\":\"username\",\"email\":\"email\",\"origin\":\"uaa\",\"externalId\":null,\"zoneId\":\"uaa\"},\"credentials\":null,\"authorities\":[],\"details\":null,\"authenticated\":true,\"authenticatedTime\":1438649464353,\"name\":\"username\"}";
        UaaAuthentication authentication1 = JsonUtils.readValue(data, UaaAuthentication.class);
        assertEquals(1438649464353l, authentication1.getAuthenticatedTime());
        assertEquals(-1l, authentication1.getExpiresAt());
        assertTrue(authentication1.isAuthenticated());
        assertNull(authentication1.getAuthContextClassRef());
        String dataWithoutTime ="{\"principal\":{\"id\":\"user-id\",\"name\":\"username\",\"email\":\"email\",\"origin\":\"uaa\",\"externalId\":null,\"zoneId\":\"uaa\"},\"credentials\":null,\"authorities\":[],\"details\":null,\"authenticated\":true,\"name\":\"username\"}";
        UaaAuthentication authentication2 = JsonUtils.readValue(dataWithoutTime, UaaAuthentication.class);
        assertEquals(-1, authentication2.getAuthenticatedTime());


        long inThePast = System.currentTimeMillis() - 1000l * 60l;
        data ="{\"principal\":{\"id\":\"user-id\",\"name\":\"username\",\"email\":\"email\",\"origin\":\"uaa\",\"externalId\":null,\"zoneId\":\"uaa\"},\"credentials\":null,\"authorities\":[],\"details\":null,\"authenticated\":true,\"authenticatedTime\":1438649464353,\"name\":\"username\", \"expiresAt\":"+inThePast+"}";
        UaaAuthentication authentication3 = JsonUtils.readValue(data, UaaAuthentication.class);
        assertEquals(1438649464353l, authentication3.getAuthenticatedTime());
        assertEquals(inThePast, authentication3.getExpiresAt());
        assertFalse(authentication3.isAuthenticated());

        long inTheFuture = System.currentTimeMillis() + 1000l * 60l;
        data ="{\"principal\":{\"id\":\"user-id\",\"name\":\"username\",\"email\":\"email\",\"origin\":\"uaa\",\"externalId\":null,\"zoneId\":\"uaa\"},\"credentials\":null,\"authorities\":[],\"details\":null,\"authenticated\":true,\"authenticatedTime\":1438649464353,\"name\":\"username\", \"expiresAt\":"+inTheFuture+"}";
        UaaAuthentication authentication4 = JsonUtils.readValue(data, UaaAuthentication.class);
        assertEquals(1438649464353l, authentication4.getAuthenticatedTime());
        assertEquals(inTheFuture, authentication4.getExpiresAt());
        assertTrue(authentication4.isAuthenticated());
    }

    @Test
    public void deserialization_with_external_groups() {
        String dataWithExternalGroups ="{\"principal\":{\"id\":\"user-id\",\"name\":\"username\",\"email\":\"email\",\"origin\":\"uaa\",\"externalId\":null,\"zoneId\":\"uaa\"},\"credentials\":null,\"authorities\":[],\"externalGroups\":[\"something\",\"or\",\"other\",\"something\"],\"details\":null,\"authenticated\":true,\"authenticatedTime\":null,\"name\":\"username\"}";
        UaaAuthentication authentication = JsonUtils.readValue(dataWithExternalGroups, UaaAuthentication.class);
        assertEquals(3, authentication.getExternalGroups().size());
        assertThat(authentication.getExternalGroups(), Matchers.containsInAnyOrder("something", "or", "other"));
        assertTrue(authentication.isAuthenticated());
    }

    @Test
    public void deserialization_with_user_attributes() {
        String dataWithoutUserAttributes ="{\"principal\":{\"id\":\"user-id\",\"name\":\"username\",\"email\":\"email\",\"origin\":\"uaa\",\"externalId\":null,\"zoneId\":\"uaa\"},\"credentials\":null,\"authorities\":[],\"externalGroups\":[\"something\",\"or\",\"other\",\"something\"],\"details\":null,\"authenticated\":true,\"authenticatedTime\":null,\"name\":\"username\", \"previousLoginSuccessTime\":1485305759347}";
        UaaAuthentication authentication = JsonUtils.readValue(dataWithoutUserAttributes, UaaAuthentication.class);
        assertEquals(3, authentication.getExternalGroups().size());
        assertThat(authentication.getExternalGroups(), Matchers.containsInAnyOrder("something", "or", "other"));
        assertTrue(authentication.isAuthenticated());

        MultiValueMap<String,String> userAttributes = new LinkedMultiValueMap<>();
        userAttributes.add(COST_CENTER, DENVER_CO);
        userAttributes.add(MANAGER, JOHN_THE_SLOTH);
        userAttributes.add(MANAGER, KARI_THE_ANT_EATER);
        authentication.setUserAttributes(userAttributes);

        String dataWithUserAttributes = JsonUtils.writeValueAsString(authentication);
        assertTrue("userAttributes should be part of the JSON", dataWithUserAttributes.contains("userAttributes"));

        UaaAuthentication authWithUserData = JsonUtils.readValue(dataWithUserAttributes, UaaAuthentication.class);
        assertNotNull(authWithUserData.getUserAttributes());
        assertThat(authWithUserData.getUserAttributes().entrySet(), everyItem(isIn(userAttributes.entrySet())));
        assertThat(userAttributes.entrySet(), everyItem(isIn(authWithUserData.getUserAttributes().entrySet())));

        assertEquals(3, authentication.getExternalGroups().size());
        assertThat(authentication.getExternalGroups(), Matchers.containsInAnyOrder("something", "or", "other"));
        assertTrue(authentication.isAuthenticated());
        assertEquals((Long) 1485305759347L, authentication.getLastLoginSuccessTime());
    }

}
