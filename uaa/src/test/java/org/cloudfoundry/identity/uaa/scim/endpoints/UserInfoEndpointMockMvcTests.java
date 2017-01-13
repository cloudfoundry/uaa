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

import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.oauth.UaaTokenServices;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UserInfo;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.utils;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.ROLES;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.USER_ATTRIBUTES;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class UserInfoEndpointMockMvcTests extends InjectedMockContextTest {

    private RandomValueStringGenerator generator = new RandomValueStringGenerator();
    private String clientId = generator.generate().toLowerCase();
    private String clientSecret = generator.generate().toLowerCase();

    private String adminToken;

    private ScimUser user;
    private String userName;

    private UaaTokenServices tokenServices;
    private Set<String> excludedClaims;
    private List<String> roles;
    private MultiValueMap<String, String> userAttributes;

    @Before
    public void setUp() throws Exception {
        adminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret", "clients.read clients.write clients.secret scim.read scim.write clients.admin");
        String authorities = "scim.read,scim.write,password.write,oauth.approvals,scim.create,openid";
        utils().createClient(this.getMockMvc(), adminToken, clientId, clientSecret, Collections.singleton("oauth"), Arrays.asList("openid", USER_ATTRIBUTES, ROLES), Arrays.asList("client_credentials", "password"), authorities);
        userName = new RandomValueStringGenerator().generate() + "@test.org";
        user = new ScimUser(null, userName, "PasswordResetUserFirst", "PasswordResetUserLast");
        user.setPrimaryEmail(user.getUserName());
        user.setPassword("secr3T");
        user = utils().createUser(getMockMvc(), adminToken, user);

        tokenServices = getWebApplicationContext().getBean(UaaTokenServices.class);
        excludedClaims = tokenServices.getExcludedClaims();

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

    @After
    public void restoreExcludedClaims() {
        tokenServices.setExcludedClaims(excludedClaims);
    }

    @Test
    public void testGetUserInfo() throws Exception {
        get_user_info("openid");
    }

    public Map<String, Object> get_user_info(String scopes) throws Exception {

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

        Map<String, Object> map = JsonUtils.readValue(response.getContentAsString(), Map.class);
        assertEquals(user.getUserName(), map.get("user_name"));
        assertEquals(user.getFamilyName(), map.get("family_name"));
        assertEquals(user.getGivenName(), map.get("given_name"));
        assertTrue(System.currentTimeMillis()/1000 - ((long) map.get("last_logon_time"))/1000 <= 5);
        return map;
    }

    @Test
    public void attributes_with_roles_and_user_attributes() throws Exception {
        Map<String, Object> info = get_user_info("openid roles user_attributes");
        Object ua = info.get(USER_ATTRIBUTES);
        assertNotNull(ua);
        assertEquals(userAttributes, ua);
        Object r = info.get(ROLES);
        assertNotNull(r);
        assertEquals(roles, r);
    }


    @Test
    public void attributes_with_no_extra_scopes() throws Exception {
        Map<String, Object> info = get_user_info("openid");
        assertNull(info.get(USER_ATTRIBUTES));
        assertNull(info.get(ROLES));
    }

    @Test
    public void testGetUserInfo_Without_PII_Token() throws Exception {
        tokenServices.setExcludedClaims(new HashSet<>(Arrays.asList("user_name","email")));
        get_user_info("openid");
    }

}

