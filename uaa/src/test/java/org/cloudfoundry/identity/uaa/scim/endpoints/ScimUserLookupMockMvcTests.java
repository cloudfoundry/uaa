/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
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

import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.oauth.client.ClientDetailsModification;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class ScimUserLookupMockMvcTests extends InjectedMockContextTest {

    private RandomValueStringGenerator generator = new RandomValueStringGenerator();
    private String clientId = generator.generate().toLowerCase();
    private String clientSecret = generator.generate().toLowerCase();

    private String scimLookupIdUserToken;
    private String adminToken;
    private TestClient testClient;

    private int testUserCount = 25, pageSize = 5;
    private static String[][] testUsers;

    private boolean originalEnabled;

    private ScimUser user;

    @Before
    public void setUp() throws Exception {
        testClient = new TestClient(getMockMvc());
        adminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret", "clients.read clients.write clients.secret scim.read scim.write");

        user = new ScimUser(null, new RandomValueStringGenerator().generate()+"@test.org", "PasswordResetUserFirst", "PasswordResetUserLast");
        user.setPrimaryEmail(user.getUserName());
        user.setPassword("secret");
        user = MockMvcUtils.utils().createUser(getMockMvc(), adminToken, user);
        user.setPassword("secret");

        originalEnabled = getWebApplicationContext().getBean(UserIdConversionEndpoints.class).isEnabled();
        getWebApplicationContext().getBean(UserIdConversionEndpoints.class).setEnabled(true);
        createScimClient(adminToken, clientId, clientSecret);
        scimLookupIdUserToken = testClient.getUserOAuthAccessToken(clientId, clientSecret, user.getUserName(), user.getPassword(), "scim.userids");
        if (testUsers==null) {
            testUsers = createUsers(adminToken, testUserCount);
        }
    }

    @After
    public void restoreEnabled() {
        getWebApplicationContext().getBean(UserIdConversionEndpoints.class).setEnabled(originalEnabled);
    }

    @Test
    public void testLookupIdFromUsername() throws Exception {
        String username = UaaTestAccounts.standard(null).getUserName();

        MockHttpServletRequestBuilder post = getIdLookupRequest(scimLookupIdUserToken, username, "eq");

        String body = getMockMvc().perform(post)
            .andExpect(status().isOk())
            .andReturn().getResponse().getContentAsString();

        validateLookupResults(new String[] {username}, body);
    }

    @Test
    public void testLookupUsingOnlyOrigin() throws Exception {
        String filter = "origin eq \"uaa\"";
        MockHttpServletRequestBuilder post = post("/ids/Users")
            .header("Authorization", "Bearer " + scimLookupIdUserToken)
            .accept(APPLICATION_JSON)
            .param("filter", filter)
            .param("startIndex", String.valueOf(1))
            .param("count", String.valueOf(50));

        getMockMvc().perform(post)
            .andExpect(status().isBadRequest());

    }

    @Test
    public void testLookupIdFromUsernameWithIncorrectScope() throws Exception {
        String token = testClient.getUserOAuthAccessToken(clientId, clientSecret, user.getUserName(), user.getPassword(), "scim.me");
        String username = UaaTestAccounts.standard(null).getUserName();

        MockHttpServletRequestBuilder post = getIdLookupRequest(token, username, "eq");

        getMockMvc().perform(post)
            .andExpect(status().isForbidden());
    }

    @Test
    public void testLookupIdFromUsernameWithNoToken() throws Exception {
        String username = UaaTestAccounts.standard(null).getUserName();

        MockHttpServletRequestBuilder post = post("/ids/Users")
            .accept(APPLICATION_JSON)
            .param("filter", "username eq \"" + username + "\"")
            .param("startIndex", String.valueOf(1))
            .param("count", String.valueOf(100));

        getMockMvc().perform(post)
            .andExpect(status().isUnauthorized());
    }

    @Test
    public void testLookupIdFromUsernameWithInvalidFilter() throws Exception {
        String username = UaaTestAccounts.standard(null).getUserName();

        MockHttpServletRequestBuilder post = getIdLookupRequest(scimLookupIdUserToken, username, "sw");

        getMockMvc().perform(post)
            .andExpect(status().isBadRequest());

        post = getIdLookupRequest(scimLookupIdUserToken, username, "co");

        getMockMvc().perform(post)
            .andExpect(status().isBadRequest());
    }

    @Test
    public void testLookupUserNameFromId() throws Exception {
        String[][] user = createUsers(adminToken, 1);
        String id = user[0][0];
        String email =  user[0][1];

        MockHttpServletRequestBuilder post = getUsernameLookupRequest(scimLookupIdUserToken, id, "eq");

        String body = getMockMvc().perform(post)
            .andExpect(status().isOk())
            .andReturn().getResponse().getContentAsString();

        validateLookupResults(new String[] {email}, body);
    }

    @Test
    public void testLookupUserNameFromIdWithIncorrectScope() throws Exception {
        String token = testClient.getUserOAuthAccessToken(clientId, clientSecret, user.getUserName(), user.getPassword(), "scim.me");
        String[][] user = createUsers(adminToken, 1);
        String id = user[0][0];

        MockHttpServletRequestBuilder post = getUsernameLookupRequest(token, id, "eq");

        getMockMvc().perform(post)
            .andExpect(status().isForbidden());
    }

    @Test
    public void testLookupIdFromUsernamePagination() throws Exception {
        StringBuilder builder = new StringBuilder();
        String[] usernames = new String[testUserCount];
        String[] ids = new String[testUserCount];
        int index = 0;
        for (String[] entry : testUsers) {
            builder.append("userName eq \"" + entry[1] + "\"");
            builder.append(" or ");
            usernames[index] = entry[1];
            ids[index++] = entry[0];
        }
        String filter = builder.substring(0, builder.length()-4);

        for (int i=0; i< testUserCount; i+= pageSize) {
            MockHttpServletRequestBuilder post = getIdLookupRequest(scimLookupIdUserToken, filter, i+1, pageSize);
            String[] expectedUsername = new String[pageSize];
            System.arraycopy(usernames, i, expectedUsername, 0, pageSize);
            String body = getMockMvc().perform(post)
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
            validateLookupResults(expectedUsername, body);
        }

    }


    private static void createScimClient(String adminAccessToken, String id, String secret) throws Exception {
        ClientDetailsModification client = new ClientDetailsModification(id, "scim", "scim.userids,scim.me", "client_credentials,password", "uaa.none");
        client.setClientSecret(secret);
        MockHttpServletRequestBuilder createClientPost = post("/oauth/clients")
            .header("Authorization", "Bearer " + adminAccessToken)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content(JsonUtils.writeValueAsBytes(client));
        getMockMvc().perform(createClientPost).andExpect(status().isCreated());
    }

    private MockHttpServletRequestBuilder getIdLookupRequest(String token, String username, String operator) {
        if (operator==null) {
            operator = "eq";
        }
        return getIdLookupRequest(token, "username "+operator+" \""+username+"\"", 1, 100);
    }

    private MockHttpServletRequestBuilder getIdLookupRequest(String token, String filter, int startIndex, int count) {
        return post("/ids/Users")
            .header("Authorization", "Bearer " + token)
            .accept(APPLICATION_JSON)
            .param("filter", filter)
            .param("startIndex", String.valueOf(startIndex))
            .param("count", String.valueOf(count));
    }

    private MockHttpServletRequestBuilder getUsernameLookupRequest(String token, String id,String operator) {
        if (operator==null) {
            operator = "eq";
        }
        return post("/ids/Users")
            .header("Authorization", "Bearer " + token)
            .accept(APPLICATION_JSON)
            .param("filter", "id "+operator+" \""+id+"\"");
    }

    private void validateLookupResults(String[] usernames, String body) throws java.io.IOException {
        Map<String, Object> map = JsonUtils.readValue(body, Map.class);
        assertTrue("Response should contain 'resources' object", map.get("resources")!=null);
        assertTrue("Response should contain 'startIndex' object", map.get("startIndex")!=null);
        assertTrue("Response should contain 'itemsPerPage' object", map.get("itemsPerPage")!=null);
        assertTrue("Response should contain 'totalResults' object", map.get("totalResults")!=null);
        List<Map<String, Object>> resources = (List<Map<String, Object>>) map.get("resources");
        assertEquals(usernames.length, resources.size());
        for (Map<String, Object> user : resources) {
            assertTrue("Response should contain 'origin' object", user.get(Origin.ORIGIN)!=null);
            assertTrue("Response should contain 'id' object", user.get("id")!=null);
            assertTrue("Response should contain 'userName' object", user.get("userName")!=null);
            String userName = (String)user.get("userName");
            boolean found = false;
            for (String s : usernames) {
                if (s.equals(userName)) {
                    found = true;
                    break;
                }
            }
            assertTrue("Received non requested user in result set '"+userName+"'", found);
        }
        for (String s : usernames) {
            boolean found = false;
            for (Map<String, Object> user : resources) {
                String userName = (String)user.get("userName");
                if (s.equals(userName)) {
                    found = true;
                    break;
                }
            }
            assertTrue("Missing user in result '"+s+"'", found);
        }
    }

    private String[][] createUsers(String token, int count) throws Exception {
        String[][] result = new String[count][];
        for (int i=0; i<count; i++) {
            String id = i>99 ? String.valueOf(i) : i > 9 ? "0" + String.valueOf(i) : "00" + String.valueOf(i);
            String email = "joe"+id+"@" + generator.generate().toLowerCase() + ".com";

            ScimUser user = new ScimUser();
            user.setUserName(email);
            user.setName(new ScimUser.Name("Joe", "User"));
            user.addEmail(email);

            byte[] requestBody = JsonUtils.writeValueAsBytes(user);
            MockHttpServletRequestBuilder post = post("/Users")
                .header("Authorization", "Bearer " + token)
                .contentType(APPLICATION_JSON)
                .content(requestBody);

            String body = getMockMvc().perform(post)
                .andExpect(status().isCreated())
                .andExpect(header().string("ETag", "\"0\""))
                .andExpect(jsonPath("$.userName").value(email))
                .andExpect(jsonPath("$.emails[0].value").value(email))
                .andExpect(jsonPath("$.name.familyName").value("User"))
                .andExpect(jsonPath("$.name.givenName").value("Joe"))
                .andReturn().getResponse().getContentAsString();
            Map<String,Object> map = JsonUtils.readValue(body, Map.class);
            result[i] = new String[] {map.get("id").toString(), email};
        }
        return result;
    }

}