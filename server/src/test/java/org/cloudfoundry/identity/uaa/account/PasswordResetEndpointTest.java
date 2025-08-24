package org.cloudfoundry.identity.uaa.account;

import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.scim.ScimMeta;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.endpoints.PasswordChange;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.scim.test.JsonObjectMatcherUtils;
import org.cloudfoundry.identity.uaa.scim.validate.PasswordValidator;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.test.MockAuthentication;
import org.cloudfoundry.identity.uaa.util.AlphanumericRandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.springframework.core.io.support.ResourcePropertySource;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Collections;
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

@ExtendWith(PollutionPreventionExtension.class)
class PasswordResetEndpointTest {

    private MockMvc mockMvc;
    private ScimUserProvisioning mockScimUserProvisioning;
    private ExpiringCodeStore mockExpiringCodeStore;
    private PasswordValidator mockPasswordValidator;
    private Date yesterday = Date.from(LocalDateTime.now().minusDays(1).atZone(ZoneId.systemDefault()).toInstant());
    private String currentZoneId;

    @BeforeEach
    void setUp() {
        mockScimUserProvisioning = mock(ScimUserProvisioning.class);
        mockExpiringCodeStore = mock(ExpiringCodeStore.class);
        mockPasswordValidator = mock(PasswordValidator.class);

        AlphanumericRandomValueStringGenerator randomValueStringGenerator = new AlphanumericRandomValueStringGenerator();
        currentZoneId = "currentZoneId-" + randomValueStringGenerator.generate();
        IdentityZoneManager mockIdentityZoneManager = mock(IdentityZoneManager.class);
        when(mockIdentityZoneManager.getCurrentIdentityZoneId()).thenReturn(currentZoneId);

        ResetPasswordService resetPasswordService = new UaaResetPasswordService(
                mockScimUserProvisioning,
                mockExpiringCodeStore,
                mockPasswordValidator,
                mock(MultitenantClientServices.class),
                mock(ResourcePropertySource.class),
                mockIdentityZoneManager);

        PasswordResetEndpoint controller = new PasswordResetEndpoint(resetPasswordService,
                mockExpiringCodeStore,
                mockIdentityZoneManager);
        mockMvc = MockMvcBuilders.standaloneSetup(controller).build();

        PasswordChange change = new PasswordChange("id001", "user@example.com", yesterday, null, null);

        when(
                mockExpiringCodeStore.generateCode(
                        eq("id001"),
                        any(Timestamp.class),
                        anyString(),
                        anyString()
                )
        )
        .thenReturn(new ExpiringCode("secret_code", new Timestamp(System.currentTimeMillis() + UaaResetPasswordService.PASSWORD_RESET_LIFETIME), "id001", null));

        when(mockExpiringCodeStore.generateCode(eq(JsonUtils.writeValueAsString(change)), any(Timestamp.class), anyString(), anyString()))
                .thenReturn(new ExpiringCode("secret_code", new Timestamp(System.currentTimeMillis() + UaaResetPasswordService.PASSWORD_RESET_LIFETIME), JsonUtils.writeValueAsString(change), null));
    }

    @Test
    void passwordResetWithClientIdAndRedirectUri() throws Exception {
        String email = "user@example.com";
        String clientId = "test-client";
        String redirectUri = "redirect.example.com";
        ScimUser user = new ScimUser("id001", email, null, null);
        user.setPasswordLastModified(yesterday);

        when(mockScimUserProvisioning.retrieveByUsernameAndOriginAndZone(
                eq(email),
                eq(OriginKeys.UAA),
                eq(currentZoneId))
        ).thenReturn(Collections.singletonList(user));

        PasswordChange change = new PasswordChange("id001", email, yesterday, clientId, redirectUri);
        when(mockExpiringCodeStore.generateCode(anyString(), any(Timestamp.class), anyString(), anyString()))
                .thenReturn(new ExpiringCode("secret_code", new Timestamp(System.currentTimeMillis() + UaaResetPasswordService.PASSWORD_RESET_LIFETIME), JsonUtils.writeValueAsString(change), null));

        MockHttpServletRequestBuilder post = post("/password_resets")
                .contentType(APPLICATION_JSON)
                .param("client_id", clientId)
                .param("redirect_uri", redirectUri)
                .content(email)
                .accept(APPLICATION_JSON);

        mockMvc.perform(post)
                .andExpect(status().isCreated());

        verify(mockExpiringCodeStore).generateCode(eq(JsonUtils.writeValueAsString(change)), any(Timestamp.class), anyString(), anyString());
    }

    @Test
    void passwordResetWithoutClientIdAndWithoutRedirectUri() throws Exception {
        String email = "user@example.com";
        ScimUser user = new ScimUser("id001", email, null, null);
        user.setPasswordLastModified(yesterday);

        when(mockScimUserProvisioning.retrieveByUsernameAndOriginAndZone(
                eq(email),
                eq(OriginKeys.UAA),
                eq(currentZoneId))
        ).thenReturn(Collections.singletonList(user));


        PasswordChange change = new PasswordChange("id001", email, yesterday, null, null);
        when(mockExpiringCodeStore.generateCode(anyString(), any(Timestamp.class), eq(null), anyString()))
                .thenReturn(new ExpiringCode("secret_code", new Timestamp(System.currentTimeMillis() + UaaResetPasswordService.PASSWORD_RESET_LIFETIME), JsonUtils.writeValueAsString(change), null));

        MockHttpServletRequestBuilder post = post("/password_resets")
                .contentType(APPLICATION_JSON)
                .content(email)
                .accept(APPLICATION_JSON);

        mockMvc.perform(post)
                .andExpect(status().isCreated());

        verify(mockExpiringCodeStore).generateCode(eq(JsonUtils.writeValueAsString(change)), any(Timestamp.class), anyString(), anyString());
    }

    @Test
    void creatingAPasswordResetWhenTheUsernameExists() throws Exception {
        ScimUser user = new ScimUser("id001", "user@example.com", null, null);
        user.setMeta(new ScimMeta(yesterday, yesterday, 0));
        user.addEmail("user@example.com");
        user.setPasswordLastModified(yesterday);
        when(mockScimUserProvisioning.retrieveByUsernameAndOriginAndZone(
                eq("user@example.com"),
                eq(OriginKeys.UAA),
                eq(currentZoneId))
        ).thenReturn(Collections.singletonList(user));

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
    void creatingAPasswordResetWhenTheUserDoesNotExist() throws Exception {
        when(mockScimUserProvisioning.query("userName eq \"user@example.com\" and origin eq \"" + OriginKeys.UAA + "\"", currentZoneId))
                .thenReturn(Collections.emptyList());

        MockHttpServletRequestBuilder post = post("/password_resets")
                .contentType(APPLICATION_JSON)
                .content("user@example.com")
                .accept(APPLICATION_JSON);

        mockMvc.perform(post)
                .andExpect(status().isNotFound());
    }

    @Test
    void creatingAPasswordResetWhenTheUserHasNonUaaOrigin() throws Exception {
        when(mockScimUserProvisioning.retrieveByUsernameAndOriginAndZone(
                eq("user@example.com"),
                eq(OriginKeys.UAA),
                eq(currentZoneId))
        ).thenReturn(Collections.emptyList());

        ScimUser user = new ScimUser("id001", "user@example.com", null, null);
        user.setMeta(new ScimMeta(new Date(System.currentTimeMillis() - (1000 * 60 * 60 * 24)), new Date(System.currentTimeMillis() - (1000 * 60 * 60 * 24)), 0));
        user.addEmail("user@example.com");
        user.setOrigin(OriginKeys.LDAP);
        when(mockScimUserProvisioning.retrieveByUsernameAndZone(eq("user@example.com"), eq(currentZoneId)))
                .thenReturn(Collections.singletonList(user));

        MockHttpServletRequestBuilder post = post("/password_resets")
                .contentType(APPLICATION_JSON)
                .content("user@example.com")
                .accept(APPLICATION_JSON);

        mockMvc.perform(post)
                .andExpect(status().isConflict())
                .andExpect(content().string(containsString("\"user_id\":\"id001\"")));
    }

    @Test
    void creatingAPasswordResetWithAUsernameContainingSpecialCharacters() throws Exception {
        ScimUser user = new ScimUser("id001", "user\"'@example.com", null, null);
        user.setMeta(new ScimMeta(yesterday, yesterday, 0));
        user.setPasswordLastModified(yesterday);
        user.addEmail("user\"'@example.com");
        when(mockScimUserProvisioning.retrieveByUsernameAndOriginAndZone(
                eq("user\"'@example.com"),
                eq(OriginKeys.UAA),
                eq(currentZoneId))
        ).thenReturn(Collections.singletonList(user));

        PasswordChange change = new PasswordChange("id001", "user\"'@example.com", yesterday, null, null);
        when(mockExpiringCodeStore.generateCode(eq(JsonUtils.writeValueAsString(change)), any(Timestamp.class), anyString(), anyString()))
                .thenReturn(new ExpiringCode("secret_code", new Timestamp(System.currentTimeMillis() + UaaResetPasswordService.PASSWORD_RESET_LIFETIME), JsonUtils.writeValueAsString(change), null));

        MockHttpServletRequestBuilder post = post("/password_resets")
                .contentType(APPLICATION_JSON)
                .content("user\"'@example.com")
                .accept(APPLICATION_JSON);

        mockMvc.perform(post)
                .andExpect(status().isCreated())
                .andExpect(content().string(containsString("\"code\":\"secret_code\"")))
                .andExpect(content().string(containsString("\"user_id\":\"id001\"")));

        when(mockScimUserProvisioning.retrieveByUsernameAndOriginAndZone(
                eq("user\"'@example.com"),
                eq(OriginKeys.UAA),
                eq(currentZoneId))
        ).thenReturn(Collections.emptyList());
        user.setOrigin(OriginKeys.LDAP);
        when(mockScimUserProvisioning.retrieveByUsernameAndZone(
                eq("user\"'@example.com"),
                eq(currentZoneId))
        ).thenReturn(Collections.singletonList(user));

        post = post("/password_resets")
                .contentType(APPLICATION_JSON)
                .content("user\"'@example.com")
                .accept(APPLICATION_JSON);

        mockMvc.perform(post)
                .andExpect(status().isConflict());
    }

    @Test
    void changingAPasswordWithAValidCode() throws Exception {
        ExpiringCode code = new ExpiringCode("secret_code", new Timestamp(System.currentTimeMillis() + UaaResetPasswordService.PASSWORD_RESET_LIFETIME),
                "{\"user_id\":\"eyedee\",\"username\":\"user@example.com\",\"passwordModifiedTime\":null,\"client_id\":\"\",\"redirect_uri\":\"\"}", null);
        when(mockExpiringCodeStore.retrieveCode("secret_code", currentZoneId)).thenReturn(code);

        ScimUser scimUser = new ScimUser("eyedee", "user@example.com", "User", "Man");
        scimUser.setMeta(new ScimMeta(new Date(System.currentTimeMillis() - (1000 * 60 * 60 * 24)), new Date(System.currentTimeMillis() - (1000 * 60 * 60 * 24)), 0));
        scimUser.addEmail("user@example.com");
        when(mockScimUserProvisioning.retrieve("eyedee", currentZoneId)).thenReturn(scimUser);
        ExpiringCode autologinCode = new ExpiringCode("autologin-code", new Timestamp(System.currentTimeMillis() + 5 * 60 * 1000), "data", AUTOLOGIN.name());
        when(mockExpiringCodeStore.generateCode(anyString(), any(Timestamp.class), eq(AUTOLOGIN.name()), anyString())).thenReturn(autologinCode);

        MockHttpServletRequestBuilder post = post("/password_change")
                .contentType(APPLICATION_JSON)
                .content("{\"code\":\"secret_code\",\"new_password\":\"new_secret\"}")
                .accept(APPLICATION_JSON);

        SecurityContextHolder.getContext().setAuthentication(new MockAuthentication());

        mockMvc.perform(post)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.user_id").value("eyedee"))
                .andExpect(jsonPath("$.username").value("user@example.com"));

        verify(mockScimUserProvisioning).changePassword("eyedee", null, "new_secret", currentZoneId);
    }

    @Test
    void changingPasswordWithInvalidCode() throws Exception {
        when(mockExpiringCodeStore.retrieveCode("invalid_code", currentZoneId))
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
    void changingAPasswordForUnverifiedUser() throws Exception {
        ExpiringCode code = new ExpiringCode("secret_code", new Timestamp(System.currentTimeMillis() + UaaResetPasswordService.PASSWORD_RESET_LIFETIME),
                "{\"user_id\":\"eyedee\",\"username\":\"user@example.com\",\"passwordModifiedTime\":null,\"client_id\":\"\",\"redirect_uri\":\"\"}", null);
        when(mockExpiringCodeStore.retrieveCode("secret_code", currentZoneId)).thenReturn(code);

        ScimUser scimUser = new ScimUser("eyedee", "user@example.com", "User", "Man");
        scimUser.setMeta(new ScimMeta(new Date(System.currentTimeMillis() - (1000 * 60 * 60 * 24)), new Date(System.currentTimeMillis() - (1000 * 60 * 60 * 24)), 0));
        scimUser.addEmail("user@example.com");
        scimUser.setVerified(false);
        when(mockScimUserProvisioning.retrieve("eyedee", currentZoneId)).thenReturn(scimUser);

        ExpiringCode autologinCode = new ExpiringCode("autologin-code", new Timestamp(System.currentTimeMillis() + 5 * 60 * 1000), "data", AUTOLOGIN.name());
        when(mockExpiringCodeStore.generateCode(anyString(), any(Timestamp.class), eq(AUTOLOGIN.name()), anyString())).thenReturn(autologinCode);

        MockHttpServletRequestBuilder post = post("/password_change")
                .contentType(APPLICATION_JSON)
                .content("{\"code\":\"secret_code\",\"new_password\":\"new_secret\"}")
                .accept(APPLICATION_JSON);

        SecurityContextHolder.getContext().setAuthentication(new MockAuthentication());

        mockMvc.perform(post)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.user_id").value("eyedee"))
                .andExpect(jsonPath("$.username").value("user@example.com"));

        verify(mockScimUserProvisioning).changePassword("eyedee", null, "new_secret", currentZoneId);
        verify(mockScimUserProvisioning).verifyUser(scimUser.getId(), -1, currentZoneId);
    }

    @Test
    void changingAPasswordWithABadRequest() throws Exception {
        MockHttpServletRequestBuilder post = post("/password_change")
                .contentType(APPLICATION_JSON)
                .content("{\"new_password\":\"new_secret\"}")
                .accept(APPLICATION_JSON);

        mockMvc.perform(post)
                .andExpect(status().isBadRequest());
    }

    @Test
    void passwordsMustSatisfyPolicy() throws Exception {
        doThrow(new InvalidPasswordException("Password flunks policy")).when(mockPasswordValidator).validate("new_secret");

        when(mockExpiringCodeStore.retrieveCode("emailed_code", currentZoneId))
                .thenReturn(new ExpiringCode("emailed_code", new Timestamp(System.currentTimeMillis() + UaaResetPasswordService.PASSWORD_RESET_LIFETIME),
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
    void changePassword_Returns422UnprocessableEntity_NewPasswordSameAsOld() throws Exception {

        Mockito.reset(mockPasswordValidator);

        when(mockExpiringCodeStore.retrieveCode("emailed_code", currentZoneId))
                .thenReturn(new ExpiringCode("emailed_code", new Timestamp(System.currentTimeMillis() + UaaResetPasswordService.PASSWORD_RESET_LIFETIME),
                        "{\"user_id\":\"eyedee\",\"username\":\"user@example.com\",\"passwordModifiedTime\":null,\"client_id\":\"\",\"redirect_uri\":\"\"}",
                        null));

        ScimUser scimUser = new ScimUser("eyedee", "user@example.com", "User", "Man");
        scimUser.setMeta(new ScimMeta(new Date(System.currentTimeMillis() - (1000 * 60 * 60 * 24)), new Date(System.currentTimeMillis() - (1000 * 60 * 60 * 24)), 0));
        scimUser.addEmail("user@example.com");
        scimUser.setVerified(true);

        when(mockScimUserProvisioning.retrieve("eyedee", currentZoneId)).thenReturn(scimUser);
        when(mockScimUserProvisioning.checkPasswordMatches("eyedee", "new_secret", currentZoneId)).thenReturn(true);

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
