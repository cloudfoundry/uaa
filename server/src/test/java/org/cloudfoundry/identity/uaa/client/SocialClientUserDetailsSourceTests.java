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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class SocialClientUserDetailsSourceTests {

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
    Map<String, String> map;

    @BeforeEach
    void setUp() {
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
        when(restTemplate.getForObject(anyString(), any())).thenReturn(map);
    }

    @Test
    void getPrincipalUsername() {
        assertThat(((SocialClientUserDetails) source.getPrincipal()).getUsername()).isEqualTo(USERNAME);
        map.remove(USERNAME);
        assertThat(((SocialClientUserDetails) source.getPrincipal()).getUsername()).isEqualTo(EMAIL);
        source.setUserInfoUrl("twitter.com");
        assertThat(((SocialClientUserDetails) source.getPrincipal()).getUsername()).isEqualTo(SCREEN_NAME);
        source.setUserInfoUrl("github.com");
        assertThat(((SocialClientUserDetails) source.getPrincipal()).getUsername()).isEqualTo(LOGIN);
        source.setUserInfoUrl("run.pivotal.io");
        assertThat(((SocialClientUserDetails) source.getPrincipal()).getUsername()).isEqualTo(USER_NAME);
        map.remove(USER_NAME);
        map.remove(EMAIL);
        assertThat(((SocialClientUserDetails) source.getPrincipal()).getUsername()).isEqualTo(ID);
    }

    @Test
    void getPrincipalUserId() {
        assertThat(((SocialClientUserDetails) source.getPrincipal()).getExternalId()).isEqualTo(ID);
        source.setUserInfoUrl("run.pivotal.io");
        assertThat(((SocialClientUserDetails) source.getPrincipal()).getExternalId()).isEqualTo(USER_ID);
    }

    @Test
    void getPrincipalFullname() {
        assertThat(((SocialClientUserDetails) source.getPrincipal()).getFullName()).isEqualTo(NAME);
        map.remove(NAME);
        assertThat(((SocialClientUserDetails) source.getPrincipal()).getFullName()).isEqualTo(FORMATTED_NAME);
        map.remove(FORMATTED_NAME);
        assertThat(((SocialClientUserDetails) source.getPrincipal()).getFullName()).isEqualTo(FULL_NAME);
        map.remove(FULL_NAME);
        assertThat(((SocialClientUserDetails) source.getPrincipal()).getFullName()).isEqualTo(GIVEN_NAME + " " + FAMILY_NAME);
        map.remove(GIVEN_NAME);
        assertThat(((SocialClientUserDetails) source.getPrincipal()).getFullName()).isEqualTo(FIRST_NAME + " " + FAMILY_NAME);
        map.remove(FAMILY_NAME);
        assertThat(((SocialClientUserDetails) source.getPrincipal()).getFullName()).isEqualTo(FIRST_NAME + " " + LAST_NAME);
        map.remove(FIRST_NAME);
        map.remove(LAST_NAME);
        assertThat(((SocialClientUserDetails) source.getPrincipal()).getFullName()).isNull();
        when(restTemplate.getForObject(anyString(), any())).thenReturn(null);
        assertThat(((SocialClientUserDetails) source.getPrincipal()).getFullName()).isNull();
    }

    @Test
    void getPrincipalFields() {
        assertThat(((SocialClientUserDetails) source.getPrincipal()).getEmail()).isEqualTo(EMAIL);
        assertThat(source.getPrincipal().getName()).isEqualTo(USERNAME);
        assertThat(source.getPrincipal().getPrincipal()).isEqualTo(USERNAME);
        assertThat(source.getPrincipal().getCredentials()).isEqualTo("N/A");
    }
}