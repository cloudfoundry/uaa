/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.openid;

import org.cloudfoundry.identity.uaa.account.UserInfoEndpoint;
import org.cloudfoundry.identity.uaa.account.UserInfoResponse;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationTestFactory;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.user.InMemoryUaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.cloudfoundry.identity.uaa.user.UserInfo;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static java.util.Collections.EMPTY_MAP;
import static java.util.Collections.EMPTY_SET;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.EMAIL;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.FAMILY_NAME;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.GIVEN_NAME;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.PHONE_NUMBER;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.USER_ATTRIBUTES;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.USER_NAME;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

public class UserInfoEndpointTests {

    public static final String MULTI_VALUE = "multi_value";
    public static final String SINGLE_VALUE = "single_value";
    private UserInfoEndpoint endpoint = new UserInfoEndpoint();
    public static final String ID = "12345";

    private final UaaUser user = new UaaUser(new UaaUserPrototype()
                    .withId(ID)
                    .withPhoneNumber("8505551234")
                    .withUsername("olds")
                    .withPassword("")
                    .withEmail("olds@vmware.com")
                    .withFamilyName("Olds")
                    .withGivenName("Dale")
                    .withCreated(new Date())
                    .withModified(new Date())
                    .withAuthorities(UaaAuthority.USER_AUTHORITIES)
                    .withOrigin(OriginKeys.UAA)
                    .withExternalId("externalId")
                    .withVerified(false)
                    .withZoneId(IdentityZoneHolder.get().getId())
                    .withSalt("12345")
                    .withPasswordLastModified(new Date())
                    .withLastLogonSuccess(1000L));
    private InMemoryUaaUserDatabase userDatabase = new InMemoryUaaUserDatabase(Collections.singleton(user));
    private UserInfo info;
    private OAuth2Request request;

    public UserInfoEndpointTests() {
        endpoint.setUserDatabase(userDatabase);
    }

    @Before
    public void setup() {
        MultiValueMap<String, String> customAttributes = new LinkedMultiValueMap<>();
        customAttributes.put(MULTI_VALUE, Arrays.asList("value1", "value2"));
        customAttributes.add(SINGLE_VALUE, "value3");
        info = new UserInfo(customAttributes);
        userDatabase.storeUserInfo(ID, info);
    }

    @Test
    public void testSunnyDay() {
        UaaUser user = userDatabase.retrieveUserByName("olds", OriginKeys.UAA);
        UaaAuthentication authentication = UaaAuthenticationTestFactory.getAuthentication(user.getId(), "olds",
                        "olds@vmware.com", new HashSet<>(Arrays.asList("openid")));

        UserInfoResponse map = endpoint.loginInfo(new OAuth2Authentication(createOauthRequest(Arrays.asList("openid")), authentication));

        assertEquals("olds", map.getUsername());
        assertEquals("Dale Olds", map.getFullName());
        assertEquals("olds@vmware.com", map.getEmail());
        assertEquals("8505551234", map.getPhoneNumber());
        assertEquals(1000, (long) map.getLastLogonSuccess());
        assertEquals(user.getId(), map.getSub());
        assertNull(map.getAttributeValue(USER_ATTRIBUTES));
    }

    @Test
    public void testSunnyDay_whenLastLogonNull_displaysNull() {
        user.setLastLogonTime(null);
        UaaUser user = userDatabase.retrieveUserByName("olds", OriginKeys.UAA);
        UaaAuthentication authentication = UaaAuthenticationTestFactory.getAuthentication(user.getId(), "olds",
            "olds@vmware.com", new HashSet<>(Arrays.asList("openid")));

        UserInfoResponse map = endpoint.loginInfo(new OAuth2Authentication(createOauthRequest(Arrays.asList("openid")), authentication));

        assertNull(map.getLastLogonSuccess());
    }

    @Test
    public void testSunnyDay_WithCustomAttributes() {
        UaaUser user = userDatabase.retrieveUserByName("olds", OriginKeys.UAA);
        UaaAuthentication authentication = UaaAuthenticationTestFactory.getAuthentication(
            user.getId(),
            "olds",
            "olds@vmware.com"
        );
        request = createOauthRequest(Arrays.asList(USER_ATTRIBUTES, "openid"));
        UserInfoResponse map = endpoint.loginInfo(new OAuth2Authentication(request, authentication));
        assertEquals("olds", map.getAttributeValue(USER_NAME));
        assertEquals("Dale Olds", map.getFullName());
        assertEquals("olds@vmware.com", map.getAttributeValue(EMAIL));
        assertEquals("8505551234", map.getAttributeValue(PHONE_NUMBER));
        assertEquals(user.getId(), map.getSub());
        assertEquals(user.getGivenName(), map.getAttributeValue(GIVEN_NAME));
        assertEquals(user.getFamilyName(), map.getAttributeValue(FAMILY_NAME));
        assertNotNull(map.getAttributeValue(USER_ATTRIBUTES));
        Map<String, Object> userAttributes = (Map<String, Object>) map.getAttributeValue(USER_ATTRIBUTES);
        assertEquals(info.get(MULTI_VALUE), userAttributes.get(MULTI_VALUE));
        assertEquals(info.get(SINGLE_VALUE), userAttributes.get(SINGLE_VALUE));
    }

    public OAuth2Request createOauthRequest(List<String> scopes) {
        return new OAuth2Request(EMPTY_MAP,
                                 "clientId",
                                 scopes.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList()),
                                 true,
                                 new HashSet<>(scopes),
                                 EMPTY_SET,
                                 null,
                                 EMPTY_SET,
                                 null);
    }

    @Test(expected = UsernameNotFoundException.class)
    public void testMissingUser() {
        UaaAuthentication authentication = UaaAuthenticationTestFactory.getAuthentication("nonexist-id", "Dale",
                        "olds@vmware.com");
        endpoint.loginInfo(new OAuth2Authentication(createOauthRequest(Arrays.asList("openid")), authentication));
    }

}
