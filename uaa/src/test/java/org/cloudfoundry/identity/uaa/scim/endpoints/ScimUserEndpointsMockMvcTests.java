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

import com.fasterxml.jackson.core.type.TypeReference;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;
import org.cloudfoundry.identity.uaa.account.UserAccountStatus;
import org.cloudfoundry.identity.uaa.approval.Approval;
import org.cloudfoundry.identity.uaa.approval.ApprovalStore;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.invitations.InvitationConstants;
import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.resources.SearchResults;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.UserAlreadyVerifiedException;
import org.cloudfoundry.identity.uaa.scim.test.JsonObjectMatcherUtils;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.SetServerNameRequestPostProcessor;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter;
import org.hamcrest.MatcherAssert;
import org.json.JSONObject;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.codestore.ExpiringCodeType.REGISTRATION;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.CookieCsrfPostProcessor.cookieCsrf;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.utils;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.startsWith;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.CLIENT_ID;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.REDIRECT_URI;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.util.StringUtils.hasText;


public class ScimUserEndpointsMockMvcTests extends InjectedMockContextTest {

    public static final String HTTP_REDIRECT_EXAMPLE_COM = "http://redirect.example.com";
    public static final String USER_PASSWORD = "pas5Word";
    private String scimReadWriteToken;
    private String scimCreateToken;
    private String uaaAdminToken;
    private String uaaAdminTokenInOtherZone;
    private RandomValueStringGenerator generator = new RandomValueStringGenerator();
    private MockMvcUtils mockMvcUtils = utils();
    private ClientDetails clientDetails;
    private ScimUserProvisioning usersRepository;
    private JdbcIdentityProviderProvisioning identityProviderProvisioning;
    private ExpiringCodeStore codeStore;

    @Before
    public void setUp() throws Exception {
        String adminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret",
                "clients.read clients.write clients.secret clients.admin uaa.admin");
        String clientId = generator.generate().toLowerCase();
        String clientSecret = generator.generate().toLowerCase();
        String authorities = "scim.read,scim.write,password.write,oauth.approvals,scim.create,uaa.admin";
        clientDetails = utils().createClient(this.getMockMvc(), adminToken, clientId, clientSecret, Collections.singleton("oauth"), Arrays.asList("foo","bar"), Collections.singletonList("client_credentials"), authorities);
        scimReadWriteToken = testClient.getClientCredentialsOAuthAccessToken(clientId, clientSecret,"scim.read scim.write password.write");
        scimCreateToken = testClient.getClientCredentialsOAuthAccessToken(clientId, clientSecret,"scim.create");
        usersRepository = getWebApplicationContext().getBean(ScimUserProvisioning.class);
        identityProviderProvisioning = getWebApplicationContext().getBean(JdbcIdentityProviderProvisioning.class);
        codeStore = getWebApplicationContext().getBean(ExpiringCodeStore.class);
        uaaAdminToken = testClient.getClientCredentialsOAuthAccessToken(clientId, clientSecret, "uaa.admin");
    }

    @After
    public void clear() {
        IdentityZoneHolder.clear();
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
        String password = hasText(user.getPassword()) ? user.getPassword() : "pas5word";
        user.setPassword(password);
        MvcResult result = createUserAndReturnResult(user, token, subdomain, switchZone)
            .andExpect(status().isCreated())
            .andExpect(header().string("ETag", "\"0\""))
            .andExpect(jsonPath("$.userName").value(user.getUserName()))
            .andExpect(jsonPath("$.emails[0].value").value(user.getUserName()))
            .andExpect(jsonPath("$.name.familyName").value(user.getFamilyName()))
            .andExpect(jsonPath("$.name.givenName").value(user.getGivenName()))
            .andReturn();
        user = JsonUtils.readValue(result.getResponse().getContentAsString(), ScimUser.class);
        user.setPassword(password);
        return user;
    }

    private ResultActions createUserAndReturnResult(ScimUser user, String token, String subdomain, String switchZone) throws Exception {
        byte[] requestBody = JsonUtils.writeValueAsBytes(user);
        MockHttpServletRequestBuilder post = post("/Users")
            .header("Authorization", "Bearer " + token)
            .contentType(APPLICATION_JSON)
            .content(requestBody);
        if (subdomain != null && !subdomain.equals("")) post.with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"));
        if (switchZone!=null) post.header(IdentityZoneSwitchingFilter.HEADER, switchZone);

        return getMockMvc().perform(post);
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
        user.getEmails().clear();
        user.setUserName(email);
        user.setPrimaryEmail(email);
        createUser(user, scimReadWriteToken, null);
    }

    @Test
    public void test_Create_User_Too_Long_Password() throws Exception {
        String email = "joe@"+generator.generate().toLowerCase()+".com";
        ScimUser user = getScimUser();
        user.setUserName(email);
        user.setPassword(new RandomValueStringGenerator(300).generate());
        ResultActions result = createUserAndReturnResult(user, scimReadWriteToken, null, null);
        result.andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.error").value("invalid_password"))
            .andExpect(jsonPath("$.message").value("Password must be no more than 255 characters in length."))
            .andExpect(jsonPath("$.error_description").value("Password must be no more than 255 characters in length."));
    }

    @Test
    public void test_Create_User_More_Than_One_Email() throws Exception {
        ScimUser scimUser = getScimUser();
        String secondEmail = "joe@"+generator.generate().toLowerCase()+".com";
        scimUser.addEmail(secondEmail);
        createUserAndReturnResult(scimUser, scimReadWriteToken, null, null)
            .andExpect(status().isBadRequest());
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
    public void createUserWithUaaAdminToken() throws Exception {
        createUser(uaaAdminToken);
    }

    @Test
    public void createUserInOtherZoneWithUaaAdminToken() throws Exception {
        IdentityZone otherIdentityZone = getIdentityZone();

        createUser(getScimUser(), uaaAdminToken, IdentityZone.getUaa().getSubdomain(), otherIdentityZone.getId());
    }

    @Test
    public void default_password_policy_does_not_allow_empty_passwords() throws Exception {
        IdentityZone otherIdentityZone = getIdentityZone();
        ScimUser scimUser = getScimUser();
        scimUser.setPassword("");

        IdentityProvider<UaaIdentityProviderDefinition> uaa =
            getWebApplicationContext().getBean(JdbcIdentityProviderProvisioning.class).retrieveByOrigin(
                OriginKeys.UAA,
                otherIdentityZone.getId()
            );

        ResultActions result = createUserAndReturnResult(scimUser, uaaAdminToken, IdentityZone.getUaa().getSubdomain(), otherIdentityZone.getId());
        result.andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.message").value("Password must be at least 1 characters in length."));
    }


    @Test
    public void createUserInOtherZoneWithUaaAdminTokenFromNonDefaultZone() throws Exception {
        IdentityZone identityZone = getIdentityZone();

        String authorities = "uaa.admin";
        clientDetails = utils().createClient(this.getMockMvc(), uaaAdminToken, "testClientId", "testClientSecret", null, null, Collections.singletonList("client_credentials"), authorities, null, identityZone);
        String uaaAdminTokenFromOtherZone = testClient.getClientCredentialsOAuthAccessToken("testClientId", "testClientSecret", "uaa.admin", identityZone.getSubdomain());

        byte[] requestBody = JsonUtils.writeValueAsBytes(getScimUser());
        MockHttpServletRequestBuilder post = post("/Users")
                .header("Authorization", "Bearer " + uaaAdminTokenFromOtherZone)
                .contentType(APPLICATION_JSON)
                .content(requestBody);
        post.with(new SetServerNameRequestPostProcessor(identityZone.getSubdomain() + ".localhost"));
        post.header(IdentityZoneSwitchingFilter.HEADER, IdentityZone.getUaa().getId());

        getMockMvc().perform(post).andExpect(status().isForbidden());
    }

    @Test
    public void verification_link() throws Exception {
        ScimUser joel = setUpScimUser();

        MockHttpServletRequestBuilder get = setUpVerificationLinkRequest(joel, scimCreateToken);

        MvcResult result = getMockMvc().perform(get)
                .andExpect(status().isOk())
                .andReturn();

        VerificationResponse verificationResponse = JsonUtils.readValue(result.getResponse().getContentAsString(), VerificationResponse.class);
        assertThat(verificationResponse.getVerifyLink().toString(), startsWith("http://localhost/verify_user"));

        String query = verificationResponse.getVerifyLink().getQuery();

        String code = getQueryStringParam(query, "code");
        assertThat(code, is(notNullValue()));

        ExpiringCode expiringCode = codeStore.retrieveCode(code);
        assertThat(expiringCode.getExpiresAt().getTime(), is(greaterThan(System.currentTimeMillis())));
        assertThat(expiringCode.getIntent(), is(REGISTRATION.name()));
        Map<String, String> data = JsonUtils.readValue(expiringCode.getData(), new TypeReference<Map<String, String>>() {});
        assertThat(data.get(InvitationConstants.USER_ID), is(notNullValue()));
        assertThat(data.get(CLIENT_ID), is(clientDetails.getClientId()));
        assertThat(data.get(REDIRECT_URI), is(HTTP_REDIRECT_EXAMPLE_COM));
    }

    @Test
    public void verification_link_in_non_default_zone() throws Exception {
        String subdomain = generator.generate().toLowerCase();
        MockMvcUtils.IdentityZoneCreationResult zoneResult = utils().createOtherIdentityZoneAndReturnResult(subdomain, getMockMvc(), getWebApplicationContext(), null);
        String zonedClientId = "zonedClientId";
        String zonedClientSecret = "zonedClientSecret";
        BaseClientDetails zonedClientDetails = (BaseClientDetails)utils().createClient(this.getMockMvc(), zoneResult.getZoneAdminToken(), zonedClientId, zonedClientSecret, Collections.singleton("oauth"), null, Arrays.asList(new String[]{"client_credentials"}), "scim.create", null, zoneResult.getIdentityZone());
        zonedClientDetails.setClientSecret(zonedClientSecret);
        String zonedScimCreateToken = utils().getClientCredentialsOAuthAccessToken(getMockMvc(), zonedClientDetails.getClientId(), zonedClientDetails.getClientSecret(), "scim.create", subdomain);

        ScimUser joel = setUpScimUser(zoneResult.getIdentityZone());

        MockHttpServletRequestBuilder get = MockMvcRequestBuilders.get("/Users/" + joel.getId() + "/verify-link")
                .header("Host", subdomain + ".localhost")
                .header("Authorization", "Bearer " + zonedScimCreateToken)
                .param("redirect_uri", HTTP_REDIRECT_EXAMPLE_COM)
                .accept(APPLICATION_JSON);

        MvcResult result = getMockMvc().perform(get)
                .andExpect(status().isOk())
                .andReturn();
        VerificationResponse verificationResponse = JsonUtils.readValue(result.getResponse().getContentAsString(), VerificationResponse.class);
        assertThat(verificationResponse.getVerifyLink().toString(), startsWith("http://" + subdomain + ".localhost/verify_user"));

        String query = verificationResponse.getVerifyLink().getQuery();

        String code = getQueryStringParam(query, "code");
        assertThat(code, is(notNullValue()));

        IdentityZoneHolder.set(zoneResult.getIdentityZone());
        ExpiringCode expiringCode = codeStore.retrieveCode(code);
        IdentityZoneHolder.clear();
        assertThat(expiringCode.getExpiresAt().getTime(), is(greaterThan(System.currentTimeMillis())));
        assertThat(expiringCode.getIntent(), is(REGISTRATION.name()));
        Map<String, String> data = JsonUtils.readValue(expiringCode.getData(), new TypeReference<Map<String, String>>() {});
        assertThat(data.get(InvitationConstants.USER_ID), is(notNullValue()));
        assertThat(data.get(CLIENT_ID), is(zonedClientDetails.getClientId()));
        assertThat(data.get(REDIRECT_URI), is(HTTP_REDIRECT_EXAMPLE_COM));
    }

    @Test
    public void verification_link_in_non_default_zone_using_switch() throws Exception {
        String subdomain = generator.generate().toLowerCase();
        MockMvcUtils.IdentityZoneCreationResult zoneResult = utils().createOtherIdentityZoneAndReturnResult(subdomain, getMockMvc(), getWebApplicationContext(), null);
        String zonedClientId = "admin";
        String zonedClientSecret = "adminsecret";
        String zonedScimCreateToken = utils().getClientCredentialsOAuthAccessToken(getMockMvc(), zonedClientId, zonedClientSecret, "uaa.admin", null);

        ScimUser joel = setUpScimUser(zoneResult.getIdentityZone());

        MockHttpServletRequestBuilder get = MockMvcRequestBuilders.get("/Users/" + joel.getId() + "/verify-link")
            .header("Host", "localhost")
            .header("Authorization", "Bearer " + zonedScimCreateToken)
            .header(IdentityZoneSwitchingFilter.SUBDOMAIN_HEADER, subdomain)
            .param("redirect_uri", HTTP_REDIRECT_EXAMPLE_COM)
            .accept(APPLICATION_JSON);

        MvcResult result = getMockMvc().perform(get)
            .andExpect(status().isOk())
            .andReturn();
        VerificationResponse verificationResponse = JsonUtils.readValue(result.getResponse().getContentAsString(), VerificationResponse.class);
        assertThat(verificationResponse.getVerifyLink().toString(), startsWith("http://" + subdomain + ".localhost/verify_user"));

        String query = verificationResponse.getVerifyLink().getQuery();

        String code = getQueryStringParam(query, "code");
        assertThat(code, is(notNullValue()));

        IdentityZoneHolder.set(zoneResult.getIdentityZone());
        ExpiringCode expiringCode = codeStore.retrieveCode(code);
        IdentityZoneHolder.clear();
        assertThat(expiringCode.getExpiresAt().getTime(), is(greaterThan(System.currentTimeMillis())));
        assertThat(expiringCode.getIntent(), is(REGISTRATION.name()));
        Map<String, String> data = JsonUtils.readValue(expiringCode.getData(), new TypeReference<Map<String, String>>() {});
        assertThat(data.get(InvitationConstants.USER_ID), is(notNullValue()));
        assertThat(data.get(CLIENT_ID), is("admin"));
        assertThat(data.get(REDIRECT_URI), is(HTTP_REDIRECT_EXAMPLE_COM));
    }
    @Test
    public void create_user_without_username() throws Exception {
        ScimUser user = new ScimUser(null, null, "Joel", "D'sa");
        user.setPassword("password");
        user.setPrimaryEmail("test@test.org");

        getMockMvc().perform(post("/Users")
            .header("Authorization", "Bearer " + scimReadWriteToken)
            .contentType(APPLICATION_JSON)
            .content(JsonUtils.writeValueAsString(user)))
            .andExpect(status().isBadRequest())
            .andExpect(content()
                .string(JsonObjectMatcherUtils.matchesJsonObject(
                    new JSONObject()
                        .put("error_description", "A username must be provided.")
                        .put("message", "A username must be provided.")
                        .put("error", "invalid_scim_resource"))));
    }

    @Test
    public void create_user_without_email() throws Exception {
        ScimUser user = new ScimUser(null, "a_user", "Joel", "D'sa");
        user.setPassword("password");

        getMockMvc().perform(post("/Users")
                .header("Authorization", "Bearer " + scimReadWriteToken)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(user)))
                .andExpect(status().isBadRequest())
                .andExpect(content()
                        .string(JsonObjectMatcherUtils.matchesJsonObject(
                                new JSONObject()
                                        .put("error_description", "Exactly one email must be provided.")
                                        .put("message", "Exactly one email must be provided.")
                                        .put("error", "invalid_scim_resource"))));
    }

    @Test
    public void create_user_then_update_without_email() throws Exception {
        ScimUser user = setUpScimUser();
        user.setEmails(null);

        getMockMvc().perform(put("/Users/" + user.getId())
                .header("Authorization", "Bearer " + scimReadWriteToken)
                .header("If-Match", "\"" + user.getVersion() + "\"")
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(user)))
                .andExpect(status().isBadRequest())
                .andExpect(content()
                        .string(JsonObjectMatcherUtils.matchesJsonObject(
                                new JSONObject()
                                        .put("error_description", "Exactly one email must be provided.")
                                        .put("message", "Exactly one email must be provided.")
                                        .put("error", "invalid_scim_resource"))));
    }


    @Test
    public void patch_user_to_inactive_then_login() throws Exception {
        ScimUser user = setUpScimUser();
        user.setVerified(true);
        boolean active = true;
        user.setActive(active);
        getMockMvc().perform(
            patch("/Users/" + user.getId())
                .header("Authorization", "Bearer " + scimReadWriteToken)
                .header("If-Match", "\"" + user.getVersion() + "\"")
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(user)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.active", equalTo(active)));

        performAuthentication(user, true);

        active = false;
        user.setActive(active);
        getMockMvc().perform(
            patch("/Users/" + user.getId())
                .header("Authorization", "Bearer " + scimReadWriteToken)
                .header("If-Match", "\"" + (user.getVersion()+1) + "\"")
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(user)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.active", equalTo(active)));

        performAuthentication(user, false);

    }

    public void performAuthentication(ScimUser user, boolean success) throws Exception {
        getMockMvc().perform(
            post("/login.do")
            .accept("text/html")
            .with(cookieCsrf())
            .param("username", user.getUserName())
            .param("password", USER_PASSWORD))
            .andDo(print())
            .andExpect(success ? authenticated() : unauthenticated());
    }

    @Test
    public void verification_link_unverified_error() throws Exception {
        ScimUser user = setUpScimUser();
        user.setVerified(true);
        usersRepository.update(user.getId(), user);

        MockHttpServletRequestBuilder get = setUpVerificationLinkRequest(user, scimCreateToken);

        getMockMvc().perform(get)
                .andExpect(status().isMethodNotAllowed())
                .andExpect(content()
                        .string(JsonObjectMatcherUtils.matchesJsonObject(
                                new JSONObject()
                                        .put("error_description", UserAlreadyVerifiedException.DESC)
                                        .put("message", UserAlreadyVerifiedException.DESC)
                                        .put("error", "user_already_verified"))));
    }

    @Test
    public void verification_link_is_authorized_endpoint() throws Exception {
        ScimUser joel = setUpScimUser();

        MockHttpServletRequestBuilder get = MockMvcRequestBuilders.get("/Users/" + joel.getId() + "/verify-link")
                .param("redirect_uri", HTTP_REDIRECT_EXAMPLE_COM)
                .accept(APPLICATION_JSON);

        getMockMvc().perform(get)
                .andExpect(status().isUnauthorized());
    }

    @Test
    public void verification_link_secured_with_scimcreate() throws Exception {
        ScimUser joel = setUpScimUser();

        MockHttpServletRequestBuilder get = setUpVerificationLinkRequest(joel, scimReadWriteToken);

        getMockMvc().perform(get)
                .andExpect(status().isForbidden());
    }

    @Test
    public void verification_link_user_not_found() throws Exception{
        MockHttpServletRequestBuilder get = MockMvcRequestBuilders.get("/Users/12345/verify-link")
            .header("Authorization", "Bearer " + scimCreateToken)
            .param("redirect_uri", HTTP_REDIRECT_EXAMPLE_COM)
            .accept(APPLICATION_JSON);

        getMockMvc().perform(get)
            .andExpect(status().isNotFound())
            .andExpect(content()
                .string(JsonObjectMatcherUtils.matchesJsonObject(
                    new JSONObject()
                        .put("error_description", "User 12345 does not exist")
                        .put("message", "User 12345 does not exist")
                        .put("error", "scim_resource_not_found"))));
    }

    @Test
    public void listUsers_in_anotherZone() throws Exception {
        String subdomain = generator.generate();
        MockMvcUtils.IdentityZoneCreationResult result = utils().createOtherIdentityZoneAndReturnResult(subdomain, getMockMvc(), getWebApplicationContext(), null);
        String zoneAdminToken = result.getZoneAdminToken();
        createUser(getScimUser(), zoneAdminToken, IdentityZone.getUaa().getSubdomain(), result.getIdentityZone().getId());

        MockHttpServletRequestBuilder get = MockMvcRequestBuilders.get("/Users")
                .header("X-Identity-Zone-Subdomain", subdomain)
                .header("Authorization", "Bearer " + zoneAdminToken)
                .accept(APPLICATION_JSON);

        MvcResult mvcResult = getMockMvc().perform(get)
                .andExpect(status().isOk())
                .andReturn();
        SearchResults searchResults = JsonUtils.readValue(mvcResult.getResponse().getContentAsString(), SearchResults.class);
        MatcherAssert.assertThat(searchResults.getResources().size(), is(1));

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

        String selfToken = testClient.getUserOAuthAccessToken("cf", "", user.getUserName(), "secret", "");

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

    @Test
    public void testUnlockAccount() throws Exception {
        ScimUser userToLockout = createUser(uaaAdminToken);
        attemptFailedLogin(5, userToLockout.getUserName(), "");

        UserAccountStatus alteredAccountStatus = new UserAccountStatus();
        alteredAccountStatus.setLocked(false);
        updateAccountStatus(userToLockout, alteredAccountStatus)
            .andExpect(status().isOk())
            .andExpect(content().json(JsonUtils.writeValueAsString(alteredAccountStatus)));

        attemptLogin(userToLockout)
            .andExpect(redirectedUrl("/"));
    }

    @Test
    public void testAccountStatusEmptyPatchDoesNotUnlock() throws Exception {
        ScimUser userToLockout = createUser(uaaAdminToken);
        attemptFailedLogin(5, userToLockout.getUserName(), "");

        updateAccountStatus(userToLockout, new UserAccountStatus())
                .andExpect(status().isOk())
                .andExpect(content().json("{}"));

        attemptLogin(userToLockout)
                .andExpect(redirectedUrl("/login?error=account_locked"));
    }

    @Test
    public void testUpdateStatusCannotLock() throws Exception {
        ScimUser user = createUser(uaaAdminToken);

        UserAccountStatus alteredAccountStatus = new UserAccountStatus();
        alteredAccountStatus.setLocked(true);
        updateAccountStatus(user, alteredAccountStatus)
                .andExpect(status().isBadRequest());

        attemptLogin(user)
            .andExpect(redirectedUrl("/"));
    }

    @Test
    public void testUnlockAccountWhenNotLocked() throws Exception {
        ScimUser userToLockout = createUser(uaaAdminToken);

        UserAccountStatus alteredAccountStatus = new UserAccountStatus();
        alteredAccountStatus.setLocked(false);
        updateAccountStatus(userToLockout, alteredAccountStatus)
          .andExpect(status().isOk())
          .andExpect(content().json(JsonUtils.writeValueAsString(alteredAccountStatus)));

        attemptLogin(userToLockout)
            .andExpect(redirectedUrl("/"));
    }

    @Test
    public void testForcePasswordExpireAccountInvalid() throws Exception {
        ScimUser user = createUser(uaaAdminToken);
        UserAccountStatus alteredAccountStatus = new UserAccountStatus();
        alteredAccountStatus.setPasswordChangeRequired(false);

        updateAccountStatus(user, alteredAccountStatus)
            .andExpect(status().isBadRequest());

        assertFalse(usersRepository.checkPasswordChangeIndividuallyRequired(user.getId()));
    }

    @Test
    public void testForcePasswordExpireAccountExternalUser() throws Exception {
        ScimUser user = createUser(uaaAdminToken);
        user.setOrigin("NOT_UAA");
        updateUser(uaaAdminToken, HttpStatus.OK.value(), user);
        UserAccountStatus alteredAccountStatus = new UserAccountStatus();
        alteredAccountStatus.setPasswordChangeRequired(true);

        updateAccountStatus(user, alteredAccountStatus)
            .andExpect(status().isBadRequest());

        assertFalse(usersRepository.checkPasswordChangeIndividuallyRequired(user.getId()));
    }

    @Test
    public void testForcePasswordChange() throws Exception {
        ScimUser user = createUser(uaaAdminToken);

        assertFalse(usersRepository.checkPasswordChangeIndividuallyRequired(user.getId()));

        UserAccountStatus alteredAccountStatus = new UserAccountStatus();
        alteredAccountStatus.setPasswordChangeRequired(true);

        updateAccountStatus(user, alteredAccountStatus)
            .andExpect(status().isOk())
            .andExpect(content().json(JsonUtils.writeValueAsString(alteredAccountStatus)));

        assertTrue(usersRepository.checkPasswordChangeIndividuallyRequired(user.getId()));
    }

    @Test
    public void testTryMultipleStatusUpdatesWithInvalidLock() throws Exception {
        ScimUser user = createUser(uaaAdminToken);

        UserAccountStatus alteredAccountStatus = new UserAccountStatus();
        alteredAccountStatus.setPasswordChangeRequired(true);
        alteredAccountStatus.setLocked(true);

        updateAccountStatus(user, alteredAccountStatus)
            .andExpect(status().isBadRequest());

        assertFalse(usersRepository.checkPasswordChangeIndividuallyRequired(user.getId()));

        attemptLogin(user)
            .andExpect(redirectedUrl("/"));
    }

    @Test
    public void testTryMultipleStatusUpdatesWithInvalidRemovalOfPasswordChange() throws Exception {
        ScimUser user = createUser(uaaAdminToken);
        attemptFailedLogin(5, user.getUserName(), "");

        UserAccountStatus alteredAccountStatus = new UserAccountStatus();
        alteredAccountStatus.setPasswordChangeRequired(false);
        alteredAccountStatus.setLocked(false);

        updateAccountStatus(user, alteredAccountStatus)
            .andExpect(status().isBadRequest());

        assertFalse(usersRepository.checkPasswordChangeIndividuallyRequired(user.getId()));

        attemptLogin(user)
            .andExpect(redirectedUrl("/login?error=account_locked"));
    }

    private ResultActions updateAccountStatus(ScimUser user, UserAccountStatus alteredAccountStatus) throws Exception {
        String jsonStatus = JsonUtils.writeValueAsString(alteredAccountStatus);
        return getMockMvc()
            .perform(
                patch("/Users/" + user.getId() + "/status")
                    .header("Authorization", "Bearer " + uaaAdminToken)
                    .accept(APPLICATION_JSON)
                    .contentType(APPLICATION_JSON)
                    .content(jsonStatus)
            );
    }

    private ResultActions attemptLogin(ScimUser user) throws Exception {
        return getMockMvc()
            .perform(post("/login.do")
                         .with(cookieCsrf())
                         .param("username", user.getUserName())
                         .param("password", user.getPassword()));
    }

    private void attemptFailedLogin(int numberOfAttempts, String username, String subdomain) throws Exception {
        String requestDomain = subdomain.equals("") ? "localhost" : subdomain + ".localhost";
        MockHttpServletRequestBuilder post = post("/login.do")
          .with(new SetServerNameRequestPostProcessor(requestDomain))
          .with(cookieCsrf())
          .param("username", username)
          .param("password", "wrong_password");
        for (int i = 0; i < numberOfAttempts ; i++) {
            getMockMvc().perform(post)
              .andExpect(redirectedUrl("/login?error=login_failure"));
        }
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
        ScimUser joel = setUpScimUser();

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
    public void testGetUserWithInvalidAttributes() throws Exception {

        String nonexistentAttribute = "displayBlaBla";

        MockHttpServletRequestBuilder get = get("/Users")
          .header("Authorization", "Bearer " + scimReadWriteToken)
          .contentType(MediaType.APPLICATION_JSON)
          .param("attributes", nonexistentAttribute)
          .accept(APPLICATION_JSON);

        MvcResult mvcResult = getMockMvc().perform(get)
          .andExpect(status().isOk())
          .andReturn();

        String body = mvcResult.getResponse().getContentAsString();

        List<Map> attList = (List) JsonUtils.readValue(body, Map.class).get("resources");
        for (Map<String, Object> attMap : attList) {
            assertNull(attMap.get(nonexistentAttribute));
        }
    }

    @Test
    public void testGetUserWithScimCreateToken() throws Exception {
        getUser(scimCreateToken,HttpStatus.FORBIDDEN.value());
    }

    @Test
    public void getUsersWithUaaAdminToken() throws Exception {
        setUpScimUser();

        MockHttpServletRequestBuilder get = MockMvcRequestBuilders.get("/Users")
            .header("Authorization", "Bearer " + uaaAdminToken)
            .accept(APPLICATION_JSON);

        getMockMvc().perform(get)
            .andExpect(status().isOk());

    }

    @Test
    public void getUserFromOtherZoneWithUaaAdminToken() throws Exception{
        IdentityZone otherIdentityZone = getIdentityZone();

        ScimUser user = setUpScimUser(otherIdentityZone);

        MockHttpServletRequestBuilder get = MockMvcRequestBuilders.get("/Users/", user.getId())
            .header("Authorization", "Bearer " + uaaAdminToken)
            .accept(APPLICATION_JSON);

        getMockMvc().perform(get)
            .andExpect(status().isOk());

    }

    protected ScimUser updateUser(String token, int status) throws Exception {
        ScimUserProvisioning usersRepository = getWebApplicationContext().getBean(ScimUserProvisioning.class);
        String email = "otheruser@"+generator.generate().toLowerCase()+".com";
        ScimUser user = new ScimUser(null, email, "Other", "User");
        user.addEmail(email);
        user = usersRepository.createUser(user, "pas5Word");
        if (status==HttpStatus.BAD_REQUEST.value()) {
            user.setUserName(null);
        } else {
            String username2 = "ou"+generator.generate().toLowerCase();
            user.setUserName(username2);
        }

        user.setName(new ScimUser.Name("Joe", "Smith"));

        return updateUser(token, status, user);
    }

    protected ScimUser updateUser(String token, int status, ScimUser user) throws Exception {
        MockHttpServletRequestBuilder put = put("/Users/" + user.getId())
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
    public void testUpdateUser_No_Username_Returns_400() throws Exception {
        updateUser(scimReadWriteToken, HttpStatus.BAD_REQUEST.value());
    }

    @Test
    public void testUpdateUserWithScimCreateToken() throws Exception {
        updateUser(scimCreateToken, HttpStatus.FORBIDDEN.value());
    }

    @Test
    public void testUpdateUserWithUaaAdminToken() throws Exception {
        updateUser(uaaAdminToken, HttpStatus.OK.value());
    }

    @Test
    public void testUpdateUserInOtherZoneWithUaaAdminToken() throws Exception {
        IdentityZone identityZone = getIdentityZone();
        ScimUser user = setUpScimUser(identityZone);
        user.setName(new ScimUser.Name("changed", "name"));

        getMockMvc().perform(put("/Users/" + user.getId())
            .header("Authorization", "Bearer " + uaaAdminToken)
            .header(IdentityZoneSwitchingFilter.HEADER, identityZone.getId())
            .header("If-Match", "\"" + user.getVersion() + "\"")
            .contentType(APPLICATION_JSON)
            .content(JsonUtils.writeValueAsBytes(user)))
            .andExpect(status().isOk())
            .andExpect(header().string("ETag", "\"1\""))
            .andExpect(jsonPath("$.userName").value(user.getUserName()))
            .andExpect(jsonPath("$.emails[0].value").value(user.getPrimaryEmail()))
            .andExpect(jsonPath("$.name.givenName").value(user.getGivenName()))
            .andExpect(jsonPath("$.name.familyName").value(user.getFamilyName()));
    }

    @Test
    public void delete_user_clears_approvals() throws Exception {
        ApprovalStore store = getWebApplicationContext().getBean(ApprovalStore.class);
        JdbcTemplate template = getWebApplicationContext().getBean(JdbcTemplate.class);
        ScimUser user = setUpScimUser();

        Approval approval = new Approval();
        approval.setClientId("cf");
        approval.setUserId(user.getId());
        approval.setScope("openid");
        approval.setStatus(Approval.ApprovalStatus.APPROVED);
        store.addApproval(approval);
        assertEquals(1, (long)template.queryForObject("select count(*) from authz_approvals where user_id=?", Integer.class, user.getId()));
        testDeleteUserWithUaaAdminToken(user);
        assertEquals(0, (long)template.queryForObject("select count(*) from authz_approvals where user_id=?", Integer.class, user.getId()));
    }

    @Test
    public void testDeleteUserWithUaaAdminToken() throws Exception {
        ScimUser user = setUpScimUser();
        testDeleteUserWithUaaAdminToken(user);
    }

    public void testDeleteUserWithUaaAdminToken(ScimUser user) throws Exception {
        getMockMvc().perform((delete("/Users/" + user.getId()))
            .header("Authorization", "Bearer " + uaaAdminToken)
            .contentType(APPLICATION_JSON)
            .content(JsonUtils.writeValueAsBytes(user)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.userName").value(user.getUserName()))
            .andExpect(jsonPath("$.emails[0].value").value(user.getPrimaryEmail()))
            .andExpect(jsonPath("$.name.givenName").value(user.getGivenName()))
            .andExpect(jsonPath("$.name.familyName").value(user.getFamilyName()));
    }

    @Test
    public void testDeleteUserInOtherZoneWithUaaAdminToken() throws Exception {
        IdentityZone identityZone = getIdentityZone();
        ScimUser user = setUpScimUser(identityZone);

        getMockMvc().perform((delete("/Users/" + user.getId()))
            .header("Authorization", "Bearer " + uaaAdminToken)
            .header(IdentityZoneSwitchingFilter.HEADER, identityZone.getId())
            .contentType(APPLICATION_JSON)
            .content(JsonUtils.writeValueAsBytes(user)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.userName").value(user.getUserName()))
            .andExpect(jsonPath("$.emails[0].value").value(user.getPrimaryEmail()))
            .andExpect(jsonPath("$.name.givenName").value(user.getGivenName()))
            .andExpect(jsonPath("$.name.familyName").value(user.getFamilyName()));
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

    @Test
    public void testCreateUserWithEmailDomainNotAllowedForOriginUaa() throws Exception {
        ScimUser user = new ScimUser(null, "abc@example.org", "First", "Last");
        user.addEmail("abc@example.org");
        user.setPassword(new RandomValueStringGenerator(2).generate());
        user.setOrigin("uaa");
        byte[] requestBody = JsonUtils.writeValueAsBytes(user);
        IdentityProvider oidcProvider = new IdentityProvider().setActive(true).setName("OIDC_test").setType(OriginKeys.OIDC10).setOriginKey(OriginKeys.OIDC10).setConfig(new OIDCIdentityProviderDefinition());
        oidcProvider.setIdentityZoneId(IdentityZoneHolder.getUaaZone().getId());
        oidcProvider.getConfig().setEmailDomain(Collections.singletonList("example.org"));

        identityProviderProvisioning.create(oidcProvider);
        try {
            MockHttpServletRequestBuilder post = post("/Users")
                .header("Authorization", "Bearer " + scimCreateToken)
                .contentType(APPLICATION_JSON)
                .content(requestBody);

            getMockMvc().perform(post)
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("The user account is set up for single sign-on. Please use one of these origin(s) : [oidc1.0]"));
        } finally {
            identityProviderProvisioning.deleteByOrigin(oidcProvider.getOriginKey(), IdentityZoneHolder.getUaaZone().getId());
        }
    }


    private MockHttpServletRequestBuilder setUpVerificationLinkRequest(ScimUser user, String token) {
        return MockMvcRequestBuilders.get("/Users/" + user.getId() + "/verify-link")
                .header("Authorization", "Bearer " + token)
                .param("redirect_uri", HTTP_REDIRECT_EXAMPLE_COM)
                .accept(APPLICATION_JSON);
    }

    private ScimUser setUpScimUser() {
        return setUpScimUser(IdentityZoneHolder.get());
    }

    private ScimUser setUpScimUser(IdentityZone zone) {
        IdentityZone original = IdentityZoneHolder.get();
        try {
            IdentityZoneHolder.set(zone);
            String email = "joe@" + generator.generate().toLowerCase() + ".com";
            ScimUser joel = new ScimUser(null, email, "Joel", "D'sa");
            joel.setVerified(false);
            joel.addEmail(email);
            joel = usersRepository.createUser(joel, USER_PASSWORD);
            return joel;
        } finally {
            IdentityZoneHolder.set(original);
        }
    }

    private String getQueryStringParam(String query, String key) {
        List<NameValuePair> params = URLEncodedUtils.parse(query, Charset.defaultCharset());
        for (NameValuePair pair : params) {
            if (key.equals(pair.getName())) {
                return pair.getValue();
            }
        }
        return null;
    }

    private IdentityZone getIdentityZone() throws Exception {
        String subdomain = generator.generate();
        return mockMvcUtils.createOtherIdentityZone(subdomain, getMockMvc(), getWebApplicationContext());
    }
}
