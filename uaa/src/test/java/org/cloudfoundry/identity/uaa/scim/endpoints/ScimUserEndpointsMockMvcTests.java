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

import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.oauth.client.ClientDetailsModification;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.SetServerNameRequestPostProcessor;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class ScimUserEndpointsMockMvcTests extends InjectedMockContextTest {

    private String scimReadWriteToken;
    private String scimCreateToken;
    private RandomValueStringGenerator generator = new RandomValueStringGenerator();
    private TestClient testClient;
    private MockMvcUtils mockMvcUtils = MockMvcUtils.utils();

    @Before
    public void setUp() throws Exception {

        testClient = new TestClient(getMockMvc());
        String adminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret",
                "clients.read clients.write clients.secret");
        String clientId = generator.generate().toLowerCase();
        String clientSecret = generator.generate().toLowerCase();
        createScimClient(adminToken, clientId, clientSecret);
        scimReadWriteToken = testClient.getClientCredentialsOAuthAccessToken(clientId, clientSecret,"scim.read scim.write password.write");
        scimCreateToken = testClient.getClientCredentialsOAuthAccessToken(clientId, clientSecret,"scim.create");
    }

    private ScimUser createUser(String token) throws Exception {
        return createUser(token, null);
    }

    private ScimUser createUser(String token, String subdomain) throws Exception {
        return createUser(getScimUser(), token, subdomain);
    }

    private ScimUser createUser(ScimUser user, String token, String subdomain) throws Exception {
        byte[] requestBody = JsonUtils.writeValueAsBytes(user);
        MockHttpServletRequestBuilder post = post("/Users")
            .header("Authorization", "Bearer " + token)
            .contentType(APPLICATION_JSON)
            .content(requestBody);
        if (subdomain != null && !subdomain.equals("")) post.with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"));

        MvcResult result = getMockMvc().perform(post)
                .andExpect(status().isCreated())
                .andExpect(header().string("ETag", "\"0\""))
                .andExpect(jsonPath("$.userName").value(user.getUserName()))
                .andExpect(jsonPath("$.emails[0].value").value(user.getUserName()))
                .andExpect(jsonPath("$.name.familyName").value(user.getFamilyName()))
                .andExpect(jsonPath("$.name.givenName").value(user.getGivenName()))
            .andReturn();

        return JsonUtils.readValue(result.getResponse().getContentAsString(), ScimUser.class);
    }

    private ScimUser getScimUser() {
        String email = "joe@"+generator.generate().toLowerCase()+".com";
        ScimUser user = new ScimUser();
        user.setUserName(email);
        user.setName(new ScimUser.Name("Joe", "User"));
        user.addEmail(email);
        return user;
    }

    @Test
    public void testCanCreateUserWithExclamationMark() throws Exception {
        String email = "joe!!@"+generator.generate().toLowerCase()+".com";
        ScimUser user = getScimUser();
        user.setUserName(email);
        user.setPrimaryEmail(email);
        createUser(user, scimReadWriteToken, null);
    }

    @Test
    public void testCreateUser() throws Exception {
        createUser(scimReadWriteToken);
    }

    @Test
    public void testCreateUserWithScimCreateToken() throws Exception {
        createUser(scimCreateToken);
    }

    @Test
    public void testVerifyUser() throws Exception {
        verifyUser(scimReadWriteToken);
    }

    @Test
    public void testVerifyUserWithScimCreateToken() throws Exception {
        verifyUser(scimCreateToken);
    }

    @Test
    public void testCreateUserInZone() throws Exception {
        String subdomain = generator.generate();
        mockMvcUtils.createOtherIdentityZone(subdomain, getMockMvc(), getWebApplicationContext());

        String zoneAdminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "admin-secret", "scim.write", subdomain);

        createUser(zoneAdminToken, subdomain);
    }

    @Test
    public void testCreateUserInOtherZoneIsUnauthorized() throws Exception {
        String subdomain = generator.generate();
        mockMvcUtils.createOtherIdentityZone(subdomain, getMockMvc(), getWebApplicationContext());

        String otherSubdomain = generator.generate();
        mockMvcUtils.createOtherIdentityZone(otherSubdomain, getMockMvc(), getWebApplicationContext());

        String zoneAdminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "admin-secret", "scim.write", subdomain);

        ScimUser user = getScimUser();

        byte[] requestBody = JsonUtils.writeValueAsBytes(user);
        MockHttpServletRequestBuilder post = post("/Users")
                .with(new SetServerNameRequestPostProcessor(otherSubdomain + ".localhost"))
                .header("Authorization", "Bearer " + zoneAdminToken)
                .contentType(APPLICATION_JSON)
                .content(requestBody);

        getMockMvc().perform(post).andExpect(status().isUnauthorized());
    }


    private void verifyUser(String token) throws Exception {
        ScimUserProvisioning usersRepository = getWebApplicationContext().getBean(ScimUserProvisioning.class);
        String email = "joe@"+generator.generate().toLowerCase()+".com";
        ScimUser joel = new ScimUser(null, email, "Joel", "D'sa");
        joel.addEmail(email);
        joel = usersRepository.createUser(joel, "password");

        MockHttpServletRequestBuilder get = MockMvcRequestBuilders.get("/Users/" + joel.getId() + "/verify")
            .header("Authorization", "Bearer " + token)
            .accept(APPLICATION_JSON);

        getMockMvc().perform(get)
            .andExpect(status().isOk())
            .andExpect(header().string("ETag", "\"0\""))
            .andExpect(jsonPath("$.userName").value(email))
            .andExpect(jsonPath("$.emails[0].value").value(email))
            .andExpect(jsonPath("$.name.familyName").value("D'sa"))
            .andExpect(jsonPath("$.name.givenName").value("Joel"))
            .andExpect(jsonPath("$.verified").value(true));
    }

    private void getUser(String token, int status) throws Exception {
        ScimUserProvisioning usersRepository = getWebApplicationContext().getBean(ScimUserProvisioning.class);
        String email = "joe@"+generator.generate().toLowerCase()+".com";
        ScimUser joel = new ScimUser(null, email, "Joel", "D'sa");
        joel.addEmail(email);
        joel = usersRepository.createUser(joel, "password");

        MockHttpServletRequestBuilder get = MockMvcRequestBuilders.get("/Users/" + joel.getId())
            .header("Authorization", "Bearer " + token)
            .accept(APPLICATION_JSON);

        if (status==HttpStatus.OK.value()) {
            getMockMvc().perform(get)
                .andExpect(status().is(status))
                .andExpect(header().string("ETag", "\"0\""))
                .andExpect(jsonPath("$.userName").value(email))
                .andExpect(jsonPath("$.emails[0].value").value(email))
                .andExpect(jsonPath("$.name.familyName").value("D'sa"))
                .andExpect(jsonPath("$.name.givenName").value("Joel"));
        } else {
            getMockMvc().perform(get)
                .andExpect(status().is(status));
        }
    }

    @Test
    public void testGetUser() throws Exception {
        getUser(scimReadWriteToken, HttpStatus.OK.value());
    }

    @Test
    public void testGetUserWithScimCreateToken() throws Exception {
        getUser(scimCreateToken,HttpStatus.FORBIDDEN.value());
    }

    private void updateUser(String token, int status) throws Exception {
        ScimUserProvisioning usersRepository = getWebApplicationContext().getBean(ScimUserProvisioning.class);
        String email = "otheruser@"+generator.generate().toLowerCase()+".com";
        ScimUser user = new ScimUser(null, email, "Other", "User");
        user.addEmail(email);
        user = usersRepository.createUser(user, "password");

        String username2 = "ou"+generator.generate().toLowerCase();
        user.setUserName(username2);
        user.setName(new ScimUser.Name("Joe", "Smith"));

        MockHttpServletRequestBuilder put = MockMvcRequestBuilders.put("/Users/" + user.getId())
            .header("Authorization", "Bearer " + token)
            .header("If-Match", "\"" + user.getVersion() + "\"")
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content(JsonUtils.writeValueAsBytes(user));

        if (status==HttpStatus.OK.value()) {
            getMockMvc().perform(put)
                .andExpect(status().isOk())
                .andExpect(header().string("ETag", "\"1\""))
                .andExpect(jsonPath("$.userName").value(username2))
                .andExpect(jsonPath("$.emails[0].value").value(email))
                .andExpect(jsonPath("$.name.givenName").value("Joe"))
                .andExpect(jsonPath("$.name.familyName").value("Smith"));
        } else {
            getMockMvc().perform(put)
                .andExpect(status().is(status));
        }
    }

    @Test
    public void testUpdateUser() throws Exception {
        updateUser(scimReadWriteToken, HttpStatus.OK.value());
    }

    @Test
    public void testUpdateUserWithScimCreateToken() throws Exception {
        updateUser(scimCreateToken, HttpStatus.FORBIDDEN.value());
    }


    private void createScimClient(String adminAccessToken, String id, String secret) throws Exception {
        ClientDetailsModification client = new ClientDetailsModification(id, "oauth", "foo,bar", "client_credentials", "scim.read,scim.write,password.write,oauth.approvals,scim.create");
        client.setClientSecret(secret);
        MockHttpServletRequestBuilder createClientPost = post("/oauth/clients")
                .header("Authorization", "Bearer " + adminAccessToken)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsBytes(client));
        getMockMvc().perform(createClientPost).andExpect(status().isCreated());
    }
}
