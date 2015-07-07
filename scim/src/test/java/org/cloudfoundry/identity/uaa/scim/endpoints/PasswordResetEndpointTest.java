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

import org.cloudfoundry.identity.uaa.TestClassNullifier;
import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.error.ExceptionReportHttpMessageConverter;
import org.cloudfoundry.identity.uaa.login.UaaResetPasswordService;
import org.cloudfoundry.identity.uaa.login.ResetPasswordService;
import org.cloudfoundry.identity.uaa.scim.ScimMeta;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.scim.validate.PasswordValidator;
import org.cloudfoundry.identity.uaa.test.MockAuthentication;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.sql.Timestamp;
import java.util.Arrays;
import java.util.Date;
import java.util.Objects;

import static org.cloudfoundry.identity.uaa.scim.endpoints.PasswordResetEndpointTest.JsonObjectMatcher.matchesJsonObject;
import static org.hamcrest.Matchers.containsString;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class PasswordResetEndpointTest extends TestClassNullifier {

    private MockMvc mockMvc;
    private ScimUserProvisioning scimUserProvisioning;
    private ExpiringCodeStore expiringCodeStore;
    private PasswordValidator passwordValidator;
    private ResetPasswordService resetPasswordService;

    @Before
    public void setUp() throws Exception {
        scimUserProvisioning = mock(ScimUserProvisioning.class);
        expiringCodeStore = mock(ExpiringCodeStore.class);
        passwordValidator = mock(PasswordValidator.class);
        resetPasswordService = new UaaResetPasswordService(scimUserProvisioning, expiringCodeStore, passwordValidator);
        PasswordResetEndpoint controller = new PasswordResetEndpoint(resetPasswordService);
        controller.setMessageConverters(new HttpMessageConverter[] { new ExceptionReportHttpMessageConverter() });
        mockMvc = MockMvcBuilders.standaloneSetup(controller).build();

        when(expiringCodeStore.generateCode(eq("id001"), any(Timestamp.class)))
                .thenReturn(new ExpiringCode("secret_code", new Timestamp(System.currentTimeMillis() + UaaResetPasswordService.PASSWORD_RESET_LIFETIME), "id001"));

        PasswordChange change = new PasswordChange("id001", "user@example.com");
        when(expiringCodeStore.generateCode(eq(JsonUtils.writeValueAsString(change)), any(Timestamp.class)))
            .thenReturn(new ExpiringCode("secret_code", new Timestamp(System.currentTimeMillis() + UaaResetPasswordService.PASSWORD_RESET_LIFETIME), "id001"));

        change = new PasswordChange("id001", "user\"'@example.com");
        when(expiringCodeStore.generateCode(eq(JsonUtils.writeValueAsString(change)), any(Timestamp.class)))
            .thenReturn(new ExpiringCode("secret_code", new Timestamp(System.currentTimeMillis() + UaaResetPasswordService.PASSWORD_RESET_LIFETIME), "id001"));
    }

    @Test
    public void testCreatingAPasswordResetWhenTheUsernameExists() throws Exception {
        ScimUser user = new ScimUser("id001", "user@example.com", null, null);
        user.setMeta(new ScimMeta(new Date(System.currentTimeMillis()-(1000*60*60*24)), new Date(System.currentTimeMillis()-(1000*60*60*24)), 0));
        user.addEmail("user@example.com");
        when(scimUserProvisioning.query("userName eq \"user@example.com\" and origin eq \"" + Origin.UAA + "\""))
                .thenReturn(Arrays.asList(user));

        MockHttpServletRequestBuilder post = post("/password_resets")
                .contentType(APPLICATION_JSON)
                .content("user@example.com")
                .accept(APPLICATION_JSON);

        mockMvc.perform(post)
                .andExpect(status().isCreated())
                .andExpect(content().string(containsString("\"code\":\"secret_code\"")))
                .andExpect(content().string(containsString("\"user_id\":\"id001\"")));
    }

    @Test
    public void testCreatingAPasswordResetWhenTheUserDoesNotExist() throws Exception {
        when(scimUserProvisioning.query("userName eq \"user@example.com\" and origin eq \"" + Origin.UAA + "\""))
                .thenReturn(Arrays.<ScimUser>asList());

        MockHttpServletRequestBuilder post = post("/password_resets")
                .contentType(APPLICATION_JSON)
                .content("user@example.com")
                .accept(APPLICATION_JSON);

        mockMvc.perform(post)
                .andExpect(status().isNotFound());
    }

    @Test
    public void testCreatingAPasswordResetWhenTheUserHasNonUaaOrigin() throws Exception {
        when(scimUserProvisioning.query("userName eq \"user@example.com\" and origin eq \"" + Origin.UAA + "\""))
            .thenReturn(Arrays.<ScimUser>asList());

        ScimUser user = new ScimUser("id001", "user@example.com", null, null);
        user.setMeta(new ScimMeta(new Date(System.currentTimeMillis()-(1000*60*60*24)), new Date(System.currentTimeMillis()-(1000*60*60*24)), 0));
        user.addEmail("user@example.com");
        user.setOrigin(Origin.LDAP);
        when(scimUserProvisioning.query("userName eq \"user@example.com\""))
            .thenReturn(Arrays.<ScimUser>asList(user));

        MockHttpServletRequestBuilder post = post("/password_resets")
            .contentType(APPLICATION_JSON)
            .content("user@example.com")
            .accept(APPLICATION_JSON);

        mockMvc.perform(post)
            .andExpect(status().isConflict())
            .andExpect(content().string(containsString("\"user_id\":\"id001\"")));
    }

    @Test
    public void testCreatingAPasswordResetWithAUsernameContainingSpecialCharacters() throws Exception {
        ScimUser user = new ScimUser("id001", "user\"'@example.com", null, null);
        user.setMeta(new ScimMeta(new Date(System.currentTimeMillis()-(1000*60*60*24)), new Date(System.currentTimeMillis()-(1000*60*60*24)), 0));
        user.addEmail("user\"'@example.com");
        when(scimUserProvisioning.query("userName eq \"user\\\"'@example.com\" and origin eq \"" + Origin.UAA + "\""))
            .thenReturn(Arrays.asList(user));

        MockHttpServletRequestBuilder post = post("/password_resets")
            .contentType(APPLICATION_JSON)
            .content("user\"'@example.com")
            .accept(APPLICATION_JSON);

        mockMvc.perform(post)
            .andExpect(status().isCreated())
            .andExpect(content().string(containsString("\"code\":\"secret_code\"")))
            .andExpect(content().string(containsString("\"user_id\":\"id001\"")));


        when(scimUserProvisioning.query("userName eq \"user\\\"'@example.com\" and origin eq \"" + Origin.UAA + "\""))
            .thenReturn(Arrays.<ScimUser>asList());
        user.setOrigin(Origin.LDAP);
        when(scimUserProvisioning.query("userName eq \"user\\\"'@example.com\""))
            .thenReturn(Arrays.asList(user));

        post = post("/password_resets")
            .contentType(APPLICATION_JSON)
            .content("user\"'@example.com")
            .accept(APPLICATION_JSON);

        mockMvc.perform(post)
            .andExpect(status().isConflict());
    }

    @Test
    public void testChangingAPasswordWithAValidCode() throws Exception {
        when(expiringCodeStore.retrieveCode("secret_code"))
                .thenReturn(new ExpiringCode("secret_code", new Timestamp(System.currentTimeMillis()+ UaaResetPasswordService.PASSWORD_RESET_LIFETIME), "eyedee"));

        ScimUser scimUser = new ScimUser("eyedee", "user@example.com", "User", "Man");
        scimUser.setMeta(new ScimMeta(new Date(System.currentTimeMillis()-(1000*60*60*24)), new Date(System.currentTimeMillis()-(1000*60*60*24)), 0));
        scimUser.addEmail("user@example.com");
        when(scimUserProvisioning.retrieve("eyedee")).thenReturn(scimUser);

        MockHttpServletRequestBuilder post = post("/password_change")
                .contentType(APPLICATION_JSON)
                .content("{\"code\":\"secret_code\",\"new_password\":\"new_secret\"}")
                .accept(APPLICATION_JSON);

        SecurityContextHolder.getContext().setAuthentication(new MockAuthentication());

        mockMvc.perform(post)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.user_id").value("eyedee"))
                .andExpect(jsonPath("$.username").value("user@example.com"));

        Mockito.verify(scimUserProvisioning).changePassword("eyedee", null, "new_secret");
    }

    @Test
    public void testChangingAPasswordForUnverifiedUser() throws Exception {
        when(expiringCodeStore.retrieveCode("secret_code"))
            .thenReturn(new ExpiringCode("secret_code", new Timestamp(System.currentTimeMillis() + UaaResetPasswordService.PASSWORD_RESET_LIFETIME), "eyedee"));

        ScimUser scimUser = new ScimUser("eyedee", "user@example.com", "User", "Man");
        scimUser.setMeta(new ScimMeta(new Date(System.currentTimeMillis() - (1000 * 60 * 60 * 24)), new Date(System.currentTimeMillis() - (1000 * 60 * 60 * 24)), 0));
        scimUser.addEmail("user@example.com");
        scimUser.setVerified(false);
        when(scimUserProvisioning.retrieve("eyedee")).thenReturn(scimUser);

        MockHttpServletRequestBuilder post = post("/password_change")
            .contentType(APPLICATION_JSON)
            .content("{\"code\":\"secret_code\",\"new_password\":\"new_secret\"}")
            .accept(APPLICATION_JSON);

        SecurityContextHolder.getContext().setAuthentication(new MockAuthentication());

        mockMvc.perform(post)
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.user_id").value("eyedee"))
            .andExpect(jsonPath("$.username").value("user@example.com"));

        Mockito.verify(scimUserProvisioning).changePassword("eyedee", null, "new_secret");
        Mockito.verify(scimUserProvisioning).verifyUser(scimUser.getId(), -1);
    }

    @Test
    public void testChangingAPasswordWithABadRequest() throws Exception {
        MockHttpServletRequestBuilder post = post("/password_change")
                .contentType(APPLICATION_JSON)
                .content("{\"new_password\":\"new_secret\"}")
                .accept(APPLICATION_JSON);

        mockMvc.perform(post)
                .andExpect(status().isBadRequest());
    }

    @Test
    public void testPasswordsMustSatisfyPolicy() throws Exception {
        doThrow(new InvalidPasswordException("Password flunks policy")).when(passwordValidator).validate("new_secret");
        MockHttpServletRequestBuilder post = post("/password_change")
                .contentType(APPLICATION_JSON)
                .content("{\"code\":\"emailed_code\",\"new_password\":\"new_secret\"}")
                .accept(APPLICATION_JSON);

        mockMvc.perform(post)
                .andExpect(status().isUnprocessableEntity())
                .andExpect(content().string(matchesJsonObject(new JSONObject().put("message", "Password flunks policy").put("error", "invalid_password"))));
    }

    @Test
    public void changePassword_Returns422UnprocessableEntity_NewPasswordSameAsOld() throws Exception {

        Mockito.reset(passwordValidator);

        when(expiringCodeStore.retrieveCode("emailed_code"))
            .thenReturn(new ExpiringCode("emailed_code", new Timestamp(System.currentTimeMillis()+ UaaResetPasswordService.PASSWORD_RESET_LIFETIME), "eyedee"));

        ScimUser scimUser = new ScimUser("eyedee", "user@example.com", "User", "Man");
        scimUser.setMeta(new ScimMeta(new Date(System.currentTimeMillis()-(1000*60*60*24)), new Date(System.currentTimeMillis()-(1000*60*60*24)), 0));
        scimUser.addEmail("user@example.com");
        scimUser.setVerified(true);

        when(scimUserProvisioning.retrieve("eyedee")).thenReturn(scimUser);
        when(scimUserProvisioning.checkPasswordMatches("eyedee", "new_secret")).thenReturn(true);

        MockHttpServletRequestBuilder post = post("/password_change")
            .contentType(APPLICATION_JSON)
            .content("{\"code\":\"emailed_code\",\"new_password\":\"new_secret\"}")
            .accept(APPLICATION_JSON);

        SecurityContextHolder.getContext().setAuthentication(new MockAuthentication());

        mockMvc.perform(post)
                .andExpect(status().isUnprocessableEntity())
                .andExpect(content().string(matchesJsonObject(new JSONObject().put("message", "Your new password cannot be the same as the old password.").put("error", "invalid_password"))));
    }

    /**
     * A {@link Matcher} that matches the {@link JSONObject} represented by the given {@link String}
     * in an order-insensitive way against an expected {@link JSONObject}.
     */
    static class JsonObjectMatcher extends BaseMatcher<String>{

        private final JSONObject expected;

        public JsonObjectMatcher(JSONObject expected) {
            this.expected = expected;
        }

        public static Matcher<? super String> matchesJsonObject(JSONObject expected){
            return new JsonObjectMatcher(expected);
        }

        @Override
        public boolean matches(Object item) {

            if(!String.class.isInstance(item)){
                return false;
            }

            if(this.expected == null && "null".equals(item)){
                return true;
            }

            JSONObject actual = null;
            try {
                actual = new JSONObject(new JSONTokener(item.toString()));
            } catch (JSONException e) {
                return false;
            }

            if(this.expected.length() != actual.length()) {
               return false;
            }

            JSONArray names = actual.names();
            for(int i = 0, len = names.length(); i < len; i++){

                try {
                    String name = names.getString(i);
                    if(!Objects.equals(expected.get(name), actual.get(name))){
                        return false;
                    }
                } catch (JSONException e) {
                    return false;
                }
            }

            return true;
        }

        @Override
        public void describeTo(Description description) {
            description.appendValue(expected);
        }
    }
}
