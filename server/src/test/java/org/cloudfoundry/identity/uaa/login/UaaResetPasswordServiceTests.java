package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.account.ConflictException;
import org.cloudfoundry.identity.uaa.account.ForgotPasswordInfo;
import org.cloudfoundry.identity.uaa.account.NotFoundException;
import org.cloudfoundry.identity.uaa.account.ResetPasswordService.ResetPasswordResponse;
import org.cloudfoundry.identity.uaa.account.UaaResetPasswordService;
import org.cloudfoundry.identity.uaa.account.event.ResetPasswordRequestEvent;
import org.cloudfoundry.identity.uaa.authentication.InvalidCodeException;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.scim.ScimMeta;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.scim.validate.PasswordValidator;
import org.cloudfoundry.identity.uaa.test.MockAuthentication;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.junit.Assert;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.core.io.support.ResourcePropertySource;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import java.sql.Timestamp;
import java.util.Collections;
import java.util.Date;

import static org.cloudfoundry.identity.uaa.util.AssertThrowsWithMessage.assertThrowsWithMessageThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.sameInstance;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.http.HttpStatus.UNPROCESSABLE_ENTITY;

class UaaResetPasswordServiceTests {

    private UaaResetPasswordService uaaResetPasswordService;
    private ExpiringCodeStore codeStore;
    private ScimUserProvisioning scimUserProvisioning;
    private PasswordValidator passwordValidator;
    private MultitenantClientServices clientDetailsService;
    private String currentZoneId;

    @BeforeEach
    void setUp() {
        SecurityContextHolder.clearContext();
        scimUserProvisioning = mock(ScimUserProvisioning.class);
        codeStore = mock(ExpiringCodeStore.class);
        passwordValidator = mock(PasswordValidator.class);
        clientDetailsService = mock(MultitenantClientServices.class);

        RandomValueStringGenerator randomValueStringGenerator = new RandomValueStringGenerator();
        currentZoneId = "currentZoneId-" + randomValueStringGenerator.generate();
        IdentityZoneManager mockIdentityZoneManager = mock(IdentityZoneManager.class);
        when(mockIdentityZoneManager.getCurrentIdentityZoneId()).thenReturn(currentZoneId);

        ResourcePropertySource resourcePropertySource = mock(ResourcePropertySource.class);
        uaaResetPasswordService = new UaaResetPasswordService(
                scimUserProvisioning,
                codeStore,
                passwordValidator,
                clientDetailsService,
                resourcePropertySource,
                mockIdentityZoneManager);
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void forgotPassword_ResetCodeIsReturnedSuccessfully() {
        ScimUser user = new ScimUser("user-id-001","exampleUser","firstName","lastName");
        user.setPasswordLastModified(new Date(1234));
        user.setPrimaryEmail("user@example.com");

        String zoneID = currentZoneId;
        when(scimUserProvisioning.retrieveByUsernameAndOriginAndZone(anyString(), anyString(), eq(zoneID))).thenReturn(Collections.singletonList(user));

        Timestamp expiresAt = new Timestamp(System.currentTimeMillis());

        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);

        when(codeStore.generateCode(eq("{\"user_id\":\"user-id-001\",\"username\":\"exampleUser\",\"passwordModifiedTime\":1234,\"client_id\":\"example\",\"redirect_uri\":\"redirect.example.com\"}"),
                                    any(Timestamp.class), anyString(), anyString())).thenReturn(new ExpiringCode("code", expiresAt, "user-id-001", null));

        ForgotPasswordInfo forgotPasswordInfo = uaaResetPasswordService.forgotPassword("exampleUser", "example", "redirect.example.com");

        verify(codeStore).expireByIntent(captor.capture(), anyString());
        assertEquals(UaaResetPasswordService.FORGOT_PASSWORD_INTENT_PREFIX+user.getId(), captor.getValue());
        assertThat(forgotPasswordInfo.getUserId(), equalTo("user-id-001"));
        assertThat(forgotPasswordInfo.getEmail(), equalTo("user@example.com"));
        ExpiringCode resetPasswordCode = forgotPasswordInfo.getResetPasswordCode();
        assertThat(resetPasswordCode.getCode(), equalTo("code"));
        assertThat(resetPasswordCode.getExpiresAt(), equalTo(expiresAt));
        assertThat(resetPasswordCode.getData(), equalTo("user-id-001"));
    }

    @Test
    void forgotPasswordFallsBackToUsernameIfNoPrimaryEmail() {
        ScimUser user = new ScimUser("user-id-001", "user@example.com", "firstName", "lastName");

        String zoneID = currentZoneId;
        when(scimUserProvisioning.retrieveByUsernameAndOriginAndZone(anyString(), anyString(), eq(zoneID))).thenReturn(Collections.singletonList(user));

        Timestamp expiresAt = new Timestamp(System.currentTimeMillis());

        when(codeStore.generateCode(anyString(), any(Timestamp.class), anyString(), anyString()))
            .thenReturn(new ExpiringCode("code", expiresAt, "user-id-001", null));

        ForgotPasswordInfo forgotPasswordInfo = uaaResetPasswordService.forgotPassword("exampleUser", "example", "redirect.example.com");

        assertThat(forgotPasswordInfo.getEmail(), equalTo("user@example.com"));
    }

    @Test
    void forgotPassword_PublishesResetPasswordRequestEvent() {
        ApplicationEventPublisher publisher = mock(ApplicationEventPublisher.class);
        Authentication authentication = mock(Authentication.class);
        uaaResetPasswordService.setApplicationEventPublisher(publisher);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        ScimUser user = new ScimUser("user-id-001", "exampleUser", "firstName", "lastName");
        user.setPrimaryEmail("user@example.com");
        String zoneId = currentZoneId;
        when(scimUserProvisioning.retrieveByUsernameAndOriginAndZone(anyString(), anyString(), eq(zoneId))).thenReturn(Collections.singletonList(user));
        Timestamp expiresAt = new Timestamp(System.currentTimeMillis());
        when(codeStore.generateCode(anyString(), any(Timestamp.class), anyString(), anyString())).thenReturn(new ExpiringCode("code", expiresAt, "user-id-001", null));

        uaaResetPasswordService.forgotPassword("exampleUser", "", "");
        ArgumentCaptor<ResetPasswordRequestEvent> captor = ArgumentCaptor.forClass(ResetPasswordRequestEvent.class);
        verify(publisher).publishEvent(captor.capture());
        ResetPasswordRequestEvent event = captor.getValue();
        assertThat(event.getSource(), equalTo("exampleUser"));
        assertThat(event.getCode(), equalTo("code"));
        assertThat(event.getEmail(), equalTo("user@example.com"));
        assertThat(event.getAuthentication(), sameInstance(authentication));
    }

    @Test
    void forgotPassword_ThrowsConflictException() {
        ScimUser user = new ScimUser("user-id-001","exampleUser","firstName","lastName");
        user.setPrimaryEmail("user@example.com");
        String zoneId = currentZoneId;
        when(scimUserProvisioning.retrieveByUsernameAndOriginAndZone(anyString(), anyString(), eq(zoneId))).thenReturn(Collections.emptyList());
        when(scimUserProvisioning.retrieveByUsernameAndZone(eq("exampleUser"), eq(zoneId))).thenReturn(Collections.singletonList(user));
        when(codeStore.generateCode(anyString(), any(Timestamp.class), eq(null), anyString())).thenReturn(new ExpiringCode("code", new Timestamp(System.currentTimeMillis()), "user-id-001", null));
        when(codeStore.retrieveCode(anyString(), anyString())).thenReturn(new ExpiringCode("code", new Timestamp(System.currentTimeMillis()), "user-id-001", null));

        try {
            uaaResetPasswordService.forgotPassword("exampleUser", "", "");
            fail();
        } catch (ConflictException e) {
            assertThat(e.getUserId(), equalTo("user-id-001"));
        }
    }

    @Test
    void forgotPassword_ThrowsNotFoundException_ScimUserNotFoundInUaa() {
        assertThrows(NotFoundException.class, () -> uaaResetPasswordService.forgotPassword("exampleUser", "", ""));
    }

    @Test
    void testResetPassword() {
        ExpiringCode code = setupResetPassword("example", "redirect.example.com/login");

        BaseClientDetails client = new BaseClientDetails();
        client.setRegisteredRedirectUri(Collections.singleton("redirect.example.com/*"));
        when(clientDetailsService.loadClientByClientId("example", currentZoneId)).thenReturn(client);

        ResetPasswordResponse response = uaaResetPasswordService.resetPassword(code, "new_secret");

        Assert.assertEquals("usermans-id", response.getUser().getId());
        Assert.assertEquals("userman", response.getUser().getUserName());
        Assert.assertEquals("redirect.example.com/login", response.getRedirectUri());
    }

    @Test
    void resetPassword_validatesNewPassword() {
        doThrow(new InvalidPasswordException("foo")).when(passwordValidator).validate("new_secret");
        ExpiringCode code1 = new ExpiringCode("secret_code", new Timestamp(System.currentTimeMillis() + 1000*60*10), "{}", null);

        assertThrows(InvalidPasswordException.class, () -> uaaResetPasswordService.resetPassword(code1, "new_secret"));
    }

    @Test
    void resetPassword_InvalidPasswordException_NewPasswordSameAsOld() {
        ScimUser user = new ScimUser("user-id", "username", "firstname", "lastname");
        user.setMeta(new ScimMeta(new Date(), new Date(), 0));
        user.setPrimaryEmail("foo@example.com");
        ExpiringCode expiringCode = new ExpiringCode("good_code",
            new Timestamp(System.currentTimeMillis() + UaaResetPasswordService.PASSWORD_RESET_LIFETIME), "{\"user_id\":\"user-id\",\"username\":\"username\",\"passwordModifiedTime\":null,\"client_id\":\"\",\"redirect_uri\":\"\"}", null);
        when(codeStore.retrieveCode("good_code", currentZoneId)).thenReturn(expiringCode);
        when(scimUserProvisioning.retrieve("user-id", currentZoneId)).thenReturn(user);
        when(scimUserProvisioning.checkPasswordMatches("user-id", "Passwo3dAsOld", currentZoneId))
            .thenThrow(new InvalidPasswordException("Your new password cannot be the same as the old password.", UNPROCESSABLE_ENTITY));
        SecurityContext securityContext = mock(SecurityContext.class);
        when(securityContext.getAuthentication()).thenReturn(new MockAuthentication());
        SecurityContextHolder.setContext(securityContext);
        try {
            uaaResetPasswordService.resetPassword(expiringCode, "Passwo3dAsOld");
            fail();
        } catch (InvalidPasswordException e) {
            assertEquals("Your new password cannot be the same as the old password.", e.getMessage());
            assertEquals(UNPROCESSABLE_ENTITY, e.getStatus());
        }
    }

    @Test
    void resetPassword_InvalidCodeData() {
        ExpiringCode expiringCode = new ExpiringCode("good_code",
                new Timestamp(System.currentTimeMillis() + UaaResetPasswordService.PASSWORD_RESET_LIFETIME), "user-id", null);
        when(codeStore.retrieveCode("good_code", currentZoneId)).thenReturn(expiringCode);
        SecurityContext securityContext = mock(SecurityContext.class);
        when(securityContext.getAuthentication()).thenReturn(new MockAuthentication());
        SecurityContextHolder.setContext(securityContext);
        try {
            uaaResetPasswordService.resetPassword(expiringCode, "password");
            fail();
        } catch (InvalidCodeException e) {
            assertEquals("Sorry, your reset password link is no longer valid. Please request a new one", e.getMessage());
        }
    }

    @Test
    void resetPassword_WithInvalidClientId() {
        ExpiringCode code = setupResetPassword("invalid_client", "redirect.example.com");
        doThrow(new NoSuchClientException("no such client")).when(clientDetailsService).loadClientByClientId("invalid_client", currentZoneId);
        ResetPasswordResponse response = uaaResetPasswordService.resetPassword(code, "new_secret");
        assertEquals("home", response.getRedirectUri());
    }

    @Test
    void resetPassword_WithNoClientId() {
        ExpiringCode code = setupResetPassword("", "redirect.example.com");
        ResetPasswordResponse response = uaaResetPasswordService.resetPassword(code, "new_secret");
        assertEquals("home", response.getRedirectUri());
    }

    @Test
    void resetPassword_WhereWildcardsDoNotMatch() {
        ExpiringCode code = setupResetPassword("example", "redirect.example.com");
        BaseClientDetails client = new BaseClientDetails();
        client.setRegisteredRedirectUri(Collections.singleton("doesnotmatch.example.com/*"));
        when(clientDetailsService.loadClientByClientId("example", currentZoneId)).thenReturn(client);

        ResetPasswordResponse response = uaaResetPasswordService.resetPassword(code, "new_secret");
        assertEquals("home", response.getRedirectUri());
    }

    @Test
    void resetPassword_WithNoRedirectUri() {
        ExpiringCode code = setupResetPassword("example", "");
        BaseClientDetails client = new BaseClientDetails();
        client.setRegisteredRedirectUri(Collections.singleton("redirect.example.com/*"));
        when(clientDetailsService.loadClientByClientId("example")).thenReturn(client);

        ResetPasswordResponse response = uaaResetPasswordService.resetPassword(code, "new_secret");
        assertEquals("home", response.getRedirectUri());
    }

    @Test
    void resetPassword_ForcedChange() {
        String userId = "user-id";
        ScimUser user = new ScimUser(userId, "username", "firstname", "lastname");
        user.setMeta(new ScimMeta(new Date(), new Date(), 0));
        user.setPrimaryEmail("foo@example.com");
        when(scimUserProvisioning.retrieve(userId, currentZoneId)).thenReturn(user);
        uaaResetPasswordService.resetUserPassword(userId, "password");

        verify(scimUserProvisioning, times(1)).updatePasswordChangeRequired(userId, false, currentZoneId);
        verify(scimUserProvisioning, times(1)).changePassword(userId, null, "password", currentZoneId);
    }

    @Test
    void resetPassword_ForcedChange_NewPasswordSameAsOld() {
        String userId = "user-id";
        ScimUser user = new ScimUser(userId, "username", "firstname", "lastname");
        user.setMeta(new ScimMeta(new Date(), new Date(), 0));
        user.setPrimaryEmail("foo@example.com");
        when(scimUserProvisioning.retrieve(userId, currentZoneId)).thenReturn(user);
        when(scimUserProvisioning.checkPasswordMatches("user-id", "password", currentZoneId))
            .thenThrow(new InvalidPasswordException("Your new password cannot be the same as the old password.", UNPROCESSABLE_ENTITY));

        assertThrows(InvalidPasswordException.class, () -> uaaResetPasswordService.resetUserPassword(userId, "password"));
    }

    @Test
    void resetPassword_forcedChange_must_verify_password_policy() {
        String userId = "user-id";
        ScimUser user = new ScimUser(userId, "username", "firstname", "lastname");
        user.setMeta(new ScimMeta(new Date(), new Date(), 0));
        user.setPrimaryEmail("foo@example.com");
        when(scimUserProvisioning.retrieve(userId, currentZoneId)).thenReturn(user);
        doThrow(new InvalidPasswordException("Password cannot contain whitespace characters.")).when(passwordValidator).validate("new password");

        assertThrowsWithMessageThat(InvalidPasswordException.class, () -> uaaResetPasswordService.resetUserPassword(userId, "new password"), containsString("Password cannot contain whitespace characters."));
    }

    private ExpiringCode setupResetPassword(String clientId, String redirectUri) {
        ScimUser user = new ScimUser("usermans-id","userman","firstName","lastName");
        user.setMeta(new ScimMeta(new Date(System.currentTimeMillis()-(1000*60*60*24)), new Date(System.currentTimeMillis()-(1000*60*60*24)), 0));
        user.setPrimaryEmail("user@example.com");
        String zoneId = currentZoneId;
        when(scimUserProvisioning.retrieve(eq("usermans-id"), eq(zoneId))).thenReturn(user);
        ExpiringCode code = new ExpiringCode("code", new Timestamp(System.currentTimeMillis()),
                                             "{\"user_id\":\"usermans-id\",\"username\":\"userman\",\"passwordModifiedTime\":null,\"client_id\":\"" + clientId + "\",\"redirect_uri\":\"" + redirectUri + "\"}", null);
        when(codeStore.retrieveCode(eq("secret_code"), anyString())).thenReturn(code);
        SecurityContext securityContext = mock(SecurityContext.class);
        when(securityContext.getAuthentication()).thenReturn(new MockAuthentication());
        SecurityContextHolder.setContext(securityContext);

        return code;
    }
}
