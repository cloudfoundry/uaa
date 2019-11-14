/*
 * ******************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * ******************************************************************************
 */

package org.cloudfoundry.identity.uaa.client;

import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentMatchers;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class SocialClientUserDetailsSourceTests{

    public static final String USER_ID = "user_id";
    public static final String EMAIL = "email";
    public static final String ID = "id";
    public static final String USERNAME = "username";
    public static final String USER_NAME = "user_name";
    public static final String LOGIN = "login";
    public static final String NAME = "name";
    public static final String FORMATTED_NAME = "formattedName";
    public static final String FULL_NAME = "fullName";
    public static final String FIRST_NAME = "firstName";
    public static final String GIVEN_NAME = "givenName";
    public static final String FAMILY_NAME = "familyName";
    public static final String LAST_NAME = "lastName";
    public static final String SCREEN_NAME = "screen_name";

    RestTemplate restTemplate;
    SocialClientUserDetailsSource source;
    Map<String,String> map;

    @Before
    public void setUp() {
        restTemplate = mock(RestTemplate.class);
        source = new SocialClientUserDetailsSource();
        source.setRestTemplate(restTemplate);
        source.setUserInfoUrl("http://not.used.anywhere.com/");
        source.afterPropertiesSet();
        map = new HashMap<>();
        map.put(EMAIL, EMAIL);
        //name values
        map.put(NAME, NAME);
        map.put(FORMATTED_NAME, FORMATTED_NAME);
        map.put(FULL_NAME, FULL_NAME);
        map.put(FIRST_NAME, FIRST_NAME);
        map.put(GIVEN_NAME, GIVEN_NAME);
        map.put(FAMILY_NAME, FAMILY_NAME);
        map.put(LAST_NAME, LAST_NAME);
        //getUserId values
        map.put(USER_ID, USER_ID);
        map.put(ID, ID);
        //getUserName values
        map.put(USERNAME, USERNAME);
        map.put(USER_NAME, USER_NAME);
        map.put(LOGIN, LOGIN);
        map.put(SCREEN_NAME, SCREEN_NAME);
        when(restTemplate.getForObject(anyString(), ArgumentMatchers.any())).thenReturn(map);
    }

    @Test
    public void testGetPrincipalUsername() {
        assertEquals(USERNAME, ((SocialClientUserDetails)source.getPrincipal()).getUsername());
        map.remove(USERNAME);
        assertEquals(EMAIL, ((SocialClientUserDetails) source.getPrincipal()).getUsername());
        source.setUserInfoUrl("twitter.com");
        assertEquals(SCREEN_NAME, ((SocialClientUserDetails)source.getPrincipal()).getUsername());
        source.setUserInfoUrl("github.com");
        assertEquals(LOGIN, ((SocialClientUserDetails)source.getPrincipal()).getUsername());
        source.setUserInfoUrl("run.pivotal.io");
        assertEquals(USER_NAME, ((SocialClientUserDetails)source.getPrincipal()).getUsername());
        map.remove(USER_NAME);
        map.remove(EMAIL);
        assertEquals(ID, ((SocialClientUserDetails) source.getPrincipal()).getUsername());
    }

    @Test
    public void testGetPrincipalUserId() {
        assertEquals(ID, ((SocialClientUserDetails)source.getPrincipal()).getExternalId());
        source.setUserInfoUrl("run.pivotal.io");
        assertEquals(USER_ID, ((SocialClientUserDetails)source.getPrincipal()).getExternalId());
    }

    @Test
    public void testGetPrincipalFullname() {
        assertEquals(NAME, ((SocialClientUserDetails)source.getPrincipal()).getFullName());
        map.remove(NAME);
        assertEquals(FORMATTED_NAME, ((SocialClientUserDetails) source.getPrincipal()).getFullName());
        map.remove(FORMATTED_NAME);
        assertEquals(FULL_NAME, ((SocialClientUserDetails) source.getPrincipal()).getFullName());
        map.remove(FULL_NAME);
        assertEquals(GIVEN_NAME + " " + FAMILY_NAME, ((SocialClientUserDetails) source.getPrincipal()).getFullName());
        map.remove(GIVEN_NAME);
        assertEquals(FIRST_NAME + " " + FAMILY_NAME, ((SocialClientUserDetails) source.getPrincipal()).getFullName());
        map.remove(FAMILY_NAME);
        assertEquals(FIRST_NAME + " " + LAST_NAME, ((SocialClientUserDetails) source.getPrincipal()).getFullName());
        map.remove(FIRST_NAME);
        map.remove(LAST_NAME);
        assertNull(((SocialClientUserDetails)source.getPrincipal()).getFullName());
    }

    @Test
    public void testGetPrincipalFields() {
        assertEquals(EMAIL, ((SocialClientUserDetails) source.getPrincipal()).getEmail());
        assertEquals(USERNAME, source.getPrincipal().getName());
        assertEquals(USERNAME, source.getPrincipal().getPrincipal());
        assertEquals("N/A", source.getPrincipal().getCredentials());
    }
}