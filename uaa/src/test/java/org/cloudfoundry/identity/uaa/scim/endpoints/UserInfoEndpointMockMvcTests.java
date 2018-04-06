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
package org.cloudfoundry.identity.uaa.scim.endpoints;

import org.cloudfoundry.identity.uaa.account.UserInfoResponse;
import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UserInfo;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.utils;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.ROLES;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.USER_ATTRIBUTES;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class UserInfoEndpointMockMvcTests extends InjectedMockContextTest {

    private RandomValueStringGenerator generator = new RandomValueStringGenerator();
    private String clientId = generator.generate().toLowerCase();
    private String clientSecret = generator.generate().toLowerCase();

    private String adminToken;

    private ScimUser user;
    private String userName;

    private List<String> roles;
    private MultiValueMap<String, String> userAttributes;

    @Before
    public void setUp() throws Exception {
        adminToken = testClient.getClientCredentialsOAuthAccessToken(
            "admin",
            "adminsecret",
            "clients.read clients.write clients.secret scim.read scim.write clients.admin"
        );
        String authorities = "scim.read,scim.write,password.write,oauth.approvals,scim.create,openid";
        utils().createClient(
            this.getMockMvc(),
            adminToken,
            clientId,
            clientSecret,
            Collections.singleton("oauth"),
            Arrays.asList("openid", USER_ATTRIBUTES, ROLES),
            Arrays.asList("client_credentials", "password"),
            authorities
        );
        userName = new RandomValueStringGenerator().generate() + "@test.org";
        user = new ScimUser(null, userName, "PasswordResetUserFirst", "PasswordResetUserLast");
        user.setPrimaryEmail(user.getUserName());
        user.setPassword("secr3T");
        user = utils().createUser(getMockMvc(), adminToken, user);
        getWebApplicationContext().getBean(UaaUserDatabase.class).updateLastLogonTime(user.getId());

        userAttributes = new LinkedMultiValueMap<>();
        userAttributes.add("single", "1");
        userAttributes.add("multi", "2");
        userAttributes.add("multi", "3");

        roles = Arrays.asList("role1", "role2", "role3");
        UserInfo userInfo = new UserInfo()
            .setUserAttributes(userAttributes)
            .setRoles(roles);

        getWebApplicationContext().getBean(UaaUserDatabase.class).storeUserInfo(user.getId(), userInfo);
    }

    @Test
    public void testGetUserInfo() throws Exception {
        UserInfoResponse userInfoResponse = getUserInfo("openid");

        assertEquals(user.getUserName(), userInfoResponse.getUserName());
        assertEquals(user.getFamilyName(), userInfoResponse.getFamilyName());
        assertEquals(user.getGivenName(), userInfoResponse.getGivenName());
        assertEquals(user.isVerified(), userInfoResponse.isEmailVerified());

        String userId = userInfoResponse.getUserId();
        assertNotNull(userId);
        Long dbPreviousLogonTime = getWebApplicationContext().getBean(UaaUserDatabase.class).retrieveUserById(userId).getPreviousLogonTime();
        assertEquals(dbPreviousLogonTime, userInfoResponse.getPreviousLogonSuccess());
    }

    @Test
    public void attributesWithRolesAndUserAttributes() throws Exception {
        UserInfoResponse userInfo = getUserInfo("openid user_attributes roles");
        Map<String, List<String>> uas = userInfo.getUserAttributes();
        assertNotNull(uas);
        assertEquals(userAttributes, uas);

        Object r = userInfo.getRoles();
        assertNotNull(r);
        assertEquals(roles, r);
    }

    @Test
    public void attributesWithNoExtraScopes() throws Exception {
        UserInfoResponse userInfo = getUserInfo("openid");
        assertNull(userInfo.getUserAttributes());
        assertNull(userInfo.getRoles());
    }

    private UserInfoResponse getUserInfo(String scopes) throws Exception {
        String userInfoToken = testClient.getUserOAuthAccessToken(
            clientId,
            clientSecret,
            user.getUserName(),
            "secr3T",
            scopes
        );

        MockHttpServletResponse response = getMockMvc().perform(
            get("/userinfo")
                .header("Authorization", "Bearer " + userInfoToken))
            .andExpect(status().isOk())
            .andReturn().getResponse();

        return JsonUtils.readValue(
            response.getContentAsString(),
            UserInfoResponse.class
        );
    }

}
