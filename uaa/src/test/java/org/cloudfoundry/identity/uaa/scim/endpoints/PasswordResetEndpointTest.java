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

import org.cloudfoundry.identity.uaa.TestClassNullifier;
import org.cloudfoundry.identity.uaa.account.PasswordResetEndpoint;
import org.cloudfoundry.identity.uaa.account.ResetPasswordService;
import org.cloudfoundry.identity.uaa.account.UaaResetPasswordService;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.scim.ScimMeta;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.scim.test.JsonObjectMatcherUtils;
import org.cloudfoundry.identity.uaa.scim.validate.PasswordValidator;
import org.cloudfoundry.identity.uaa.test.MockAuthentication;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.web.ExceptionReportHttpMessageConverter;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.json.JSONObject;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.core.io.support.ResourcePropertySource;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.sql.Timestamp;
import java.util.Arrays;
import java.util.Date;

import static org.cloudfoundry.identity.uaa.codestore.ExpiringCodeType.AUTOLOGIN;
import static org.hamcrest.Matchers.containsString;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
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
    private MultitenantClientServices clientDetailsService;
    private ResourcePropertySource resourcePropertySource;
    Date yesterday = new Date(System.currentTimeMillis()-(1000*60*60*24));

    @Before
    public void setUp() throws Exception {
        scimUserProvisioning = mock(ScimUserProvisioning.class);
        expiringCodeStore = mock(ExpiringCodeStore.class);
        passwordValidator = mock(PasswordValidator.class);
        clientDetailsService = mock(MultitenantClientServices.class);
        resourcePropertySource = mock(ResourcePropertySource.class);
        resetPasswordService = new UaaResetPasswordService(scimUserProvisioning, expiringCodeStore, passwordValidator, clientDetailsService, resourcePropertySource);
        PasswordResetEndpoint controller = new PasswordResetEndpoint(resetPasswordService);
        controller.setCodeStore(expiringCodeStore);
        controller.setMessageConverters(new HttpMessageConverter[] { new ExceptionReportHttpMessageConverter() });
        mockMvc = MockMvcBuilders.standaloneSetup(controller).build();

        PasswordChange change = new PasswordChange("id001", "user@example.com", yesterday, null, null);



        when(
            expiringCodeStore.generateCode(
                eq("id001"),
                any(Timestamp.class),
                anyString(),
                anyString()
            )
        )
                .thenReturn(new ExpiringCode("secret_code", new Timestamp(System.currentTimeMillis() + UaaResetPasswordService.PASSWORD_RESET_LIFETIME), "id001", null));

        when(expiringCodeStore.generateCode(eq(JsonUtils.writeValueAsString(change)), any(Timestamp.class), anyString(), anyString()))
            .thenReturn(new ExpiringCode("secret_code", new Timestamp(System.currentTimeMillis() + UaaResetPasswordService.PASSWORD_RESET_LIFETIME), JsonUtils.writeValueAsString(change), null));
       }

    @Test
    public void password_reset_with_client_id_and_redirect_uri() throws Exception {
        String email = "user@example.com";
        String clientId = "test-client";
        String redirectUri = "redirect.example.com";
        ScimUser user = new ScimUser("id001", email, null, null);
        user.setPasswordLastModified(yesterday);

        when(scimUserProvisioning.query("userName eq \"" + email + "\" and origin eq \"" + OriginKeys.UAA + "\"", IdentityZoneHolder.get().getId()))
                .thenReturn(Arrays.asList(user));

        PasswordChange change = new PasswordChange("id001", email, yesterday, clientId, redirectUri);
        when(expiringCodeStore.generateCode(anyString(), any(Timestamp.class), anyString(), anyString()))
                .thenReturn(new ExpiringCode("secret_code", new Timestamp(System.currentTimeMillis() + UaaResetPasswordService.PASSWORD_RESET_LIFETIME), JsonUtils.writeValueAsString(change), null));

        MockHttpServletRequestBuilder post = post("/password_resets")
                .contentType(APPLICATION_JSON)
                .param("client_id", clientId)
                .param("redirect_uri", redirectUri)
                .content(email)
                .accept(APPLICATION_JSON);

        mockMvc.perform(post)
                .andExpect(status().isCreated());

        verify(expiringCodeStore).generateCode(eq(JsonUtils.writeValueAsString(change)), any(Timestamp.class), anyString(), anyString());
    }

    @Test
    public void password_reset_without_client_id_and_without_redirect_uri() throws Exception {
        String email = "user@example.com";
        ScimUser user = new ScimUser("id001", email, null, null);
        user.setPasswordLastModified(yesterday);

        when(scimUserProvisioning.query("userName eq \"" + email + "\" and origin eq \"" + OriginKeys.UAA + "\"", IdentityZoneHolder.get().getId()))
                .thenReturn(Arrays.asList(user));

        PasswordChange change = new PasswordChange("id001", email, yesterday, null, null);
        when(expiringCodeStore.generateCode(anyString(), any(Timestamp.class), eq(null), anyString()))
                .thenReturn(new ExpiringCode("secret_code", new Timestamp(System.currentTimeMillis() + UaaResetPasswordService.PASSWORD_RESET_LIFETIME), JsonUtils.writeValueAsString(change), null));

        MockHttpServletRequestBuilder post = post("/password_resets")
                .contentType(APPLICATION_JSON)
                .content(email)
                .accept(APPLICATION_JSON);

        mockMvc.perform(post)
                .andExpect(status().isCreated());

        verify(expiringCodeStore).generateCode(eq(JsonUtils.writeValueAsString(change)), any(Timestamp.class), anyString(), anyString());
    }

    @Test
    public void testCreatingAPasswordResetWhenTheUsernameExists() throws Exception {
        ScimUser user = new ScimUser("id001", "user@example.com", null, null);
        user.setMeta(new ScimMeta(yesterday, yesterday, 0));
        user.addEmail("user@example.com");
        user.setPasswordLastModified(yesterday);
        when(scimUserProvisioning.query("userName eq \"user@example.com\" and origin eq \"" + OriginKeys.UAA + "\"", IdentityZoneHolder.get().getId()))
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
        when(scimUserProvisioning.query("userName eq \"user@example.com\" and origin eq \"" + OriginKeys.UAA + "\"", IdentityZoneHolder.get().getId()))
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
        when(scimUserProvisioning.query("userName eq \"user@example.com\" and origin eq \"" + OriginKeys.UAA + "\"", IdentityZoneHolder.get().getId()))
            .thenReturn(Arrays.<ScimUser>asList());

        ScimUser user = new ScimUser("id001", "user@example.com", null, null);
        user.setMeta(new ScimMeta(new Date(System.currentTimeMillis()-(1000*60*60*24)), new Date(System.currentTimeMillis()-(1000*60*60*24)), 0));
        user.addEmail("user@example.com");
        user.setOrigin(OriginKeys.LDAP);
        when(scimUserProvisioning.query("userName eq \"user@example.com\"", IdentityZoneHolder.get().getId()))
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
        user.setMeta(new ScimMeta(yesterday, yesterday, 0));
        user.setPasswordLastModified(yesterday);
        user.addEmail("user\"'@example.com");
        when(scimUserProvisioning.query("userName eq \"user\\\"'@example.com\" and origin eq \"" + OriginKeys.UAA + "\"", IdentityZoneHolder.get().getId()))
            .thenReturn(Arrays.asList(user));

        PasswordChange change = new PasswordChange("id001", "user\"'@example.com", yesterday, null, null);
        when(expiringCodeStore.generateCode(eq(JsonUtils.writeValueAsString(change)), any(Timestamp.class), anyString(), anyString()))
            .thenReturn(new ExpiringCode("secret_code", new Timestamp(System.currentTimeMillis() + UaaResetPasswordService.PASSWORD_RESET_LIFETIME), JsonUtils.writeValueAsString(change), null));

        MockHttpServletRequestBuilder post = post("/password_resets")
            .contentType(APPLICATION_JSON)
            .content("user\"'@example.com")
            .accept(APPLICATION_JSON);

        mockMvc.perform(post)
            .andExpect(status().isCreated())
            .andExpect(content().string(containsString("\"code\":\"secret_code\"")))
            .andExpect(content().string(containsString("\"user_id\":\"id001\"")));

        when(scimUserProvisioning.query("userName eq \"user\\\"'@example.com\" and origin eq \"" + OriginKeys.UAA + "\"", IdentityZoneHolder.get().getId()))
            .thenReturn(Arrays.<ScimUser>asList());
        user.setOrigin(OriginKeys.LDAP);
        when(scimUserProvisioning.query("userName eq \"user\\\"'@example.com\"", IdentityZoneHolder.get().getId()))
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
        ExpiringCode code = new ExpiringCode("secret_code", new Timestamp(System.currentTimeMillis() + UaaResetPasswordService.PASSWORD_RESET_LIFETIME),
                                                    "{\"user_id\":\"eyedee\",\"username\":\"user@example.com\",\"passwordModifiedTime\":null,\"client_id\":\"\",\"redirect_uri\":\"\"}", null);
        when(expiringCodeStore.retrieveCode("secret_code", IdentityZoneHolder.get().getId())).thenReturn(code);

        ScimUser scimUser = new ScimUser("eyedee", "user@example.com", "User", "Man");
        scimUser.setMeta(new ScimMeta(new Date(System.currentTimeMillis() - (1000 * 60 * 60 * 24)), new Date(System.currentTimeMillis() - (1000 * 60 * 60 * 24)), 0));
        scimUser.addEmail("user@example.com");
        when(scimUserProvisioning.retrieve("eyedee", IdentityZoneHolder.get().getId())).thenReturn(scimUser);
        ExpiringCode autologinCode = new ExpiringCode("autologin-code", new Timestamp(System.currentTimeMillis() + 5 * 60 * 1000), "data", AUTOLOGIN.name());
        when(expiringCodeStore.generateCode(anyString(), any(Timestamp.class), eq(AUTOLOGIN.name()), anyString())).thenReturn(autologinCode);

        MockHttpServletRequestBuilder post = post("/password_change")
                .contentType(APPLICATION_JSON)
                .content("{\"code\":\"secret_code\",\"new_password\":\"new_secret\"}")
                .accept(APPLICATION_JSON);

        SecurityContextHolder.getContext().setAuthentication(new MockAuthentication());

        mockMvc.perform(post)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.user_id").value("eyedee"))
                .andExpect(jsonPath("$.username").value("user@example.com"));

        verify(scimUserProvisioning).changePassword("eyedee", null, "new_secret", IdentityZoneHolder.get().getId());
    }

    @Test
    public void changing_password_with_invalid_code() throws Exception {
        when(expiringCodeStore.retrieveCode("invalid_code", IdentityZoneHolder.get().getId()))
            .thenReturn(null);

        MockHttpServletRequestBuilder post = post("/password_change")
            .contentType(APPLICATION_JSON)
            .content("{\"code\":\"secret_code\",\"new_password\":\"new_secret\"}");

        mockMvc.perform(post)
            .andExpect(status().isUnprocessableEntity())
            .andExpect(content().string(JsonObjectMatcherUtils.matchesJsonObject(new JSONObject()
                .put("error_description", "Sorry, your reset password link is no longer valid. Please request a new one")
                .put("message", "Sorry, your reset password link is no longer valid. Please request a new one")
                .put("error", "invalid_code"))));
    }

    @Test
    public void testChangingAPasswordForUnverifiedUser() throws Exception {
        ExpiringCode code = new ExpiringCode("secret_code", new Timestamp(System.currentTimeMillis() + UaaResetPasswordService.PASSWORD_RESET_LIFETIME),
                                                    "{\"user_id\":\"eyedee\",\"username\":\"user@example.com\",\"passwordModifiedTime\":null,\"client_id\":\"\",\"redirect_uri\":\"\"}", null);
        when(expiringCodeStore.retrieveCode("secret_code", IdentityZoneHolder.get().getId())).thenReturn(code);

        ScimUser scimUser = new ScimUser("eyedee", "user@example.com", "User", "Man");
        scimUser.setMeta(new ScimMeta(new Date(System.currentTimeMillis() - (1000 * 60 * 60 * 24)), new Date(System.currentTimeMillis() - (1000 * 60 * 60 * 24)), 0));
        scimUser.addEmail("user@example.com");
        scimUser.setVerified(false);
        when(scimUserProvisioning.retrieve("eyedee", IdentityZoneHolder.get().getId())).thenReturn(scimUser);

        ExpiringCode autologinCode = new ExpiringCode("autologin-code", new Timestamp(System.currentTimeMillis() + 5 * 60 * 1000), "data", AUTOLOGIN.name());
        when(expiringCodeStore.generateCode(anyString(), any(Timestamp.class), eq(AUTOLOGIN.name()), anyString())).thenReturn(autologinCode);

        MockHttpServletRequestBuilder post = post("/password_change")
            .contentType(APPLICATION_JSON)
            .content("{\"code\":\"secret_code\",\"new_password\":\"new_secret\"}")
            .accept(APPLICATION_JSON);

        SecurityContextHolder.getContext().setAuthentication(new MockAuthentication());

        mockMvc.perform(post)
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.user_id").value("eyedee"))
            .andExpect(jsonPath("$.username").value("user@example.com"));

        verify(scimUserProvisioning).changePassword("eyedee", null, "new_secret", IdentityZoneHolder.get().getId());
        verify(scimUserProvisioning).verifyUser(scimUser.getId(), -1, IdentityZoneHolder.get().getId());
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

        when(expiringCodeStore.retrieveCode("emailed_code", IdentityZoneHolder.get().getId()))
            .thenReturn(new ExpiringCode("emailed_code", new Timestamp(System.currentTimeMillis()+ UaaResetPasswordService.PASSWORD_RESET_LIFETIME),
                "{\"user_id\":\"eyedee\",\"username\":\"user@example.com\",\"passwordModifiedTime\":null,\"client_id\":\"\",\"redirect_uri\":\"\"}",
                null));

        MockHttpServletRequestBuilder post = post("/password_change")
                .contentType(APPLICATION_JSON)
                .content("{\"code\":\"emailed_code\",\"new_password\":\"new_secret\"}")
                .accept(APPLICATION_JSON);

        mockMvc.perform(post)
                .andExpect(status().isUnprocessableEntity())
                .andExpect(content().string(JsonObjectMatcherUtils.matchesJsonObject(new JSONObject().put("error_description", "Password flunks policy").put("message", "Password flunks policy").put("error", "invalid_password"))));
    }

    @Test
    public void changePassword_Returns422UnprocessableEntity_NewPasswordSameAsOld() throws Exception {

        Mockito.reset(passwordValidator);

        when(expiringCodeStore.retrieveCode("emailed_code", IdentityZoneHolder.get().getId()))
            .thenReturn(new ExpiringCode("emailed_code", new Timestamp(System.currentTimeMillis()+ UaaResetPasswordService.PASSWORD_RESET_LIFETIME),
                    "{\"user_id\":\"eyedee\",\"username\":\"user@example.com\",\"passwordModifiedTime\":null,\"client_id\":\"\",\"redirect_uri\":\"\"}",
                    null));

        ScimUser scimUser = new ScimUser("eyedee", "user@example.com", "User", "Man");
        scimUser.setMeta(new ScimMeta(new Date(System.currentTimeMillis()-(1000*60*60*24)), new Date(System.currentTimeMillis()-(1000*60*60*24)), 0));
        scimUser.addEmail("user@example.com");
        scimUser.setVerified(true);

        when(scimUserProvisioning.retrieve("eyedee", IdentityZoneHolder.get().getId())).thenReturn(scimUser);
        when(scimUserProvisioning.checkPasswordMatches("eyedee", "new_secret", IdentityZoneHolder.get().getId())).thenReturn(true);

        MockHttpServletRequestBuilder post = post("/password_change")
            .contentType(APPLICATION_JSON)
            .content("{\"code\":\"emailed_code\",\"new_password\":\"new_secret\"}")
            .accept(APPLICATION_JSON);

        SecurityContextHolder.getContext().setAuthentication(new MockAuthentication());

        mockMvc.perform(post)
                .andExpect(status().isUnprocessableEntity())
                .andExpect(content().string(JsonObjectMatcherUtils.matchesJsonObject(new JSONObject().put("error_description", "Your new password cannot be the same as the old password.").put("message", "Your new password cannot be the same as the old password.").put("error", "invalid_password"))));
    }
}
