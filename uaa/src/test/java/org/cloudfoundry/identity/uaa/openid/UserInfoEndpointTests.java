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
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static java.util.Collections.EMPTY_MAP;
import static java.util.Collections.EMPTY_SET;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.ROLES;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.USER_ATTRIBUTES;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.USER_ID;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

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
        .withLastLogonSuccess(1000L)
        .withPreviousLogonSuccess(1000L));
    private final UaaUser verifiedUser = new UaaUser(new UaaUserPrototype()
        .withId(ID + "v")
        .withPhoneNumber("8505551234")
        .withUsername("somename")
        .withPassword("")
        .withEmail("comr@dstal.in")
        .withVerified(true)
        .withFamilyName("Olds")
        .withGivenName("Dale")
        .withCreated(new Date())
        .withModified(new Date())
        .withAuthorities(UaaAuthority.USER_AUTHORITIES)
        .withOrigin(OriginKeys.UAA)
        .withExternalId("externalId")
        .withZoneId(IdentityZoneHolder.get().getId())
        .withSalt("12345")
        .withPasswordLastModified(new Date())
        .withLastLogonSuccess(1000L)
        .withPreviousLogonSuccess(1000L));
    private InMemoryUaaUserDatabase userDatabase = new InMemoryUaaUserDatabase(Arrays.asList(user, verifiedUser));
    private UserInfo info;
    private OAuth2Request request;
    private List<String> roles;

    public UserInfoEndpointTests() {
        endpoint.setUserDatabase(userDatabase);
    }

    @Before
    public void setup() {
        MultiValueMap<String, String> customAttributes = new LinkedMultiValueMap<>();
        customAttributes.put(MULTI_VALUE, Arrays.asList("value1", "value2"));
        customAttributes.add(SINGLE_VALUE, "value3");
        roles = Arrays.asList("group1", "group1");
        info = new UserInfo()
            .setUserAttributes(customAttributes)
            .setRoles(roles);
        userDatabase.storeUserInfo(ID, info);
    }

    @Test
    public void testSunnyDay() {
        UaaUser user = userDatabase.retrieveUserByName("olds", OriginKeys.UAA);
        UaaAuthentication authentication = UaaAuthenticationTestFactory.getAuthentication(user.getId(), "olds",
            "olds@vmware.com", new HashSet<>(Arrays.asList("openid")));

        UserInfoResponse userInfoResponse = endpoint.loginInfo(new OAuth2Authentication(createOauthRequest(Arrays.asList("openid")), authentication));

        assertEquals("olds", userInfoResponse.getUserName());
        assertEquals("Dale Olds", userInfoResponse.getFullName());
        assertEquals("olds@vmware.com", userInfoResponse.getEmail());
        assertEquals("8505551234", userInfoResponse.getPhoneNumber());
        assertFalse(userInfoResponse.isEmailVerified());
        assertEquals(1000, (long) userInfoResponse.getPreviousLogonSuccess());
        assertEquals(user.getId(), userInfoResponse.getSub());
        assertNull(userInfoResponse.getUserAttributes());
    }

    @Test
    public void testVerifiedUser() {
        UaaUser user = userDatabase.retrieveUserByName("somename", OriginKeys.UAA);
        UaaAuthentication authentication = UaaAuthenticationTestFactory.getAuthentication(user.getId(), "somename",
            "comr@dstal.in", new HashSet<>(Arrays.asList("openid")));

        UserInfoResponse userInfoResponse = endpoint.loginInfo(new OAuth2Authentication(createOauthRequest(Arrays.asList("openid")), authentication));

        assertEquals("somename", userInfoResponse.getUserName());
        assertTrue(userInfoResponse.isEmailVerified());
    }

    @Test
    public void testSunnyDay_whenLastLogonNull_displaysNull() {
        user.setPreviousLogonTime(null);
        UaaUser user = userDatabase.retrieveUserByName("olds", OriginKeys.UAA);
        UaaAuthentication authentication = UaaAuthenticationTestFactory.getAuthentication(user.getId(), "olds",
            "olds@vmware.com", new HashSet<>(Arrays.asList("openid")));

        UserInfoResponse map = endpoint.loginInfo(new OAuth2Authentication(createOauthRequest(Arrays.asList("openid")), authentication));

        assertNull(map.getPreviousLogonSuccess());
    }

    @Test
    public void testSunnyDay_WithCustomAttributes() {
        UaaUser user = userDatabase.retrieveUserByName("olds", OriginKeys.UAA);
        UaaAuthentication authentication = UaaAuthenticationTestFactory.getAuthentication(
            user.getId(),
            "olds",
            "olds@vmware.com"
        );
        request = createOauthRequest(Arrays.asList(USER_ATTRIBUTES, "openid", ROLES));
        UserInfoResponse map = endpoint.loginInfo(new OAuth2Authentication(request, authentication));
        assertEquals("olds", map.getUserName());
        assertEquals("Dale Olds", map.getFullName());
        assertEquals("olds@vmware.com", map.getEmail());
        assertEquals("8505551234", map.getPhoneNumber());
        assertEquals(user.getId(), map.getSub());
        assertEquals(user.getGivenName(), map.getGivenName());
        assertEquals(user.getFamilyName(), map.getFamilyName());
        assertNotNull(map.getUserAttributes());
        Map<String, List<String>> userAttributes = map.getUserAttributes();
        assertEquals(info.getUserAttributes().get(MULTI_VALUE), userAttributes.get(MULTI_VALUE));
        assertEquals(info.getUserAttributes().get(SINGLE_VALUE), userAttributes.get(SINGLE_VALUE));
        assertNull(userAttributes.get(USER_ID));
        List<String> infoRoles = info.getRoles();
        assertNotNull(infoRoles);
        assertThat(infoRoles, containsInAnyOrder(roles.toArray()));

        //remove permissions
        request = createOauthRequest(Arrays.asList("openid"));
        map = endpoint.loginInfo(new OAuth2Authentication(request, authentication));
        assertNull(map.getUserAttributes());
        assertNull(map.getRoles());
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
