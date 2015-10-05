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
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.SetServerNameRequestPostProcessor;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import java.util.Collections;

import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.utils;
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
    private MockMvcUtils mockMvcUtils = utils();

    @Before
    public void setUp() throws Exception {
        testClient = new TestClient(getMockMvc());
        String adminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret",
                "clients.read clients.write clients.secret");
        String clientId = generator.generate().toLowerCase();
        String clientSecret = generator.generate().toLowerCase();
        String authorities = "scim.read,scim.write,password.write,oauth.approvals,scim.create";
        utils().createClient(this.getMockMvc(), adminToken, clientId, clientSecret, "oauth", "foo,bar", Collections.singletonList(MockMvcUtils.GrantType.client_credentials), authorities);
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
        return createUser(user,token,subdomain, null);
    }

    private ScimUser createUser(ScimUser user, String token, String subdomain, String switchZone) throws Exception {
        byte[] requestBody = JsonUtils.writeValueAsBytes(user);
        MockHttpServletRequestBuilder post = post("/Users")
            .header("Authorization", "Bearer " + token)
            .contentType(APPLICATION_JSON)
            .content(requestBody);
        if (subdomain != null && !subdomain.equals("")) post.with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"));
        if (switchZone!=null) post.header(IdentityZoneSwitchingFilter.HEADER, switchZone);

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
    public void testCreateUserInZoneUsingAdminClient() throws Exception {
        String subdomain = generator.generate();
        mockMvcUtils.createOtherIdentityZone(subdomain, getMockMvc(), getWebApplicationContext());

        String zoneAdminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "admin-secret", "scim.write", subdomain);

        createUser(zoneAdminToken, subdomain);
    }

    @Test
    public void testCreateUserInZoneUsingZoneAdminUser() throws Exception {
        String subdomain = generator.generate();
        MockMvcUtils.IdentityZoneCreationResult result = utils().createOtherIdentityZoneAndReturnResult(subdomain, getMockMvc(), getWebApplicationContext(), null);
        String zoneAdminToken = result.getZoneAdminToken();
        createUser(getScimUser(), zoneAdminToken, IdentityZone.getUaa().getSubdomain(), result.getIdentityZone().getId());
    }

    @Test
    public void testUserSelfAccess_Get_and_Post() throws Exception {
        ScimUser user = getScimUser();
        user.setPassword("secret");
        user = createUser(user, scimReadWriteToken, IdentityZone.getUaa().getSubdomain());
        user.setPassword("secret");

        String selfToken = testClient.getUserOAuthAccessToken("cf","",user.getUserName(),"secret","");

        user.setName(new ScimUser.Name("Given1","Family1"));
        user = updateUser(selfToken, HttpStatus.OK.value(), user );

        user = getAndReturnUser(HttpStatus.OK.value(), user, selfToken);
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
        joel = usersRepository.createUser(joel, "pas5Word");

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
        joel = usersRepository.createUser(joel, "pas5Word");

        getAndReturnUser(status, joel, token);
    }

    protected ScimUser getAndReturnUser(int status, ScimUser user, String token) throws Exception {
        MockHttpServletRequestBuilder get = MockMvcRequestBuilders.get("/Users/" + user.getId())
            .header("Authorization", "Bearer " + token)
            .accept(APPLICATION_JSON);

        if (status== HttpStatus.OK.value()) {
            String json = getMockMvc().perform(get)
                .andExpect(status().is(status))
                .andExpect(header().string("ETag", "\""+user.getVersion()+"\""))
                .andExpect(jsonPath("$.userName").value(user.getPrimaryEmail()))
                .andExpect(jsonPath("$.emails[0].value").value(user.getPrimaryEmail()))
                .andExpect(jsonPath("$.name.familyName").value(user.getFamilyName()))
                .andExpect(jsonPath("$.name.givenName").value(user.getGivenName()))
                .andReturn().getResponse().getContentAsString();
            return JsonUtils.readValue(json, ScimUser.class);
        } else {
            getMockMvc().perform(get)
                .andExpect(status().is(status));
            return null;
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

    protected ScimUser updateUser(String token, int status) throws Exception {
        ScimUserProvisioning usersRepository = getWebApplicationContext().getBean(ScimUserProvisioning.class);
        String email = "otheruser@"+generator.generate().toLowerCase()+".com";
        ScimUser user = new ScimUser(null, email, "Other", "User");
        user.addEmail(email);
        user = usersRepository.createUser(user, "pas5Word");

        String username2 = "ou"+generator.generate().toLowerCase();
        user.setUserName(username2);
        user.setName(new ScimUser.Name("Joe", "Smith"));

        return updateUser(token, status, user);
    }

    protected ScimUser updateUser(String token, int status, ScimUser user) throws Exception {
        MockHttpServletRequestBuilder put = MockMvcRequestBuilders.put("/Users/" + user.getId())
            .header("Authorization", "Bearer " + token)
            .header("If-Match", "\"" + user.getVersion() + "\"")
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content(JsonUtils.writeValueAsBytes(user));
        if (status == HttpStatus.OK.value()) {
            String json = getMockMvc().perform(put)
                .andExpect(status().isOk())
                .andExpect(header().string("ETag", "\"1\""))
                .andExpect(jsonPath("$.userName").value(user.getUserName()))
                .andExpect(jsonPath("$.emails[0].value").value(user.getPrimaryEmail()))
                .andExpect(jsonPath("$.name.givenName").value(user.getGivenName()))
                .andExpect(jsonPath("$.name.familyName").value(user.getFamilyName()))
                .andReturn().getResponse().getContentAsString();

            return JsonUtils.readValue(json, ScimUser.class);
        } else {
            getMockMvc().perform(put)
                .andExpect(status().is(status));
            return null;
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

    @Test
    public void cannotCreateUserWithInvalidPasswordInDefaultZone() throws Exception {
        ScimUser user = getScimUser();
        user.setPassword(new RandomValueStringGenerator(260).generate());
        byte[] requestBody = JsonUtils.writeValueAsBytes(user);
        MockHttpServletRequestBuilder post = post("/Users")
                .header("Authorization", "Bearer " + scimCreateToken)
                .contentType(APPLICATION_JSON)
                .content(requestBody);

        getMockMvc().perform(post)
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_password"))
                .andExpect(jsonPath("$.message").value("Password must be no more than 255 characters in length."));
    }

}
