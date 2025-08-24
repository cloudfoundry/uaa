package org.cloudfoundry.identity.uaa.invitations;

import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.message.MessageService;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.provider.NoSuchClientException;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.web.client.HttpClientErrorException;

import java.sql.Timestamp;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.cloudfoundry.identity.uaa.codestore.ExpiringCodeType.INVITATION;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LDAP;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.cloudfoundry.identity.uaa.invitations.EmailInvitationsService.EMAIL;
import static org.cloudfoundry.identity.uaa.invitations.EmailInvitationsService.USER_ID;
import static org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils.CLIENT_ID;
import static org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils.REDIRECT_URI;
import static org.mockito.Mockito.anyInt;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(PollutionPreventionExtension.class)
@ExtendWith(MockitoExtension.class)
class EmailInvitationsServiceTests {

    @Mock
    ExpiringCodeStore mockExpiringCodeStore;

    @Mock
    MessageService mockMessageService;

    @Mock
    ScimUserProvisioning mockScimUserProvisioning;

    @Mock
    MultitenantClientServices mockClientDetailsService;

    @Mock
    IdentityZoneManager mockIdentityZoneManager;

    @InjectMocks
    EmailInvitationsService emailInvitationsService;

    private String zoneId;

    @BeforeEach
    void setUp() {
        RandomValueStringGenerator generator = new RandomValueStringGenerator();
        zoneId = "zoneId-" + generator.generate();
        when(mockIdentityZoneManager.getCurrentIdentityZoneId()).thenReturn(zoneId);
    }

    @Test
    void acceptInvitationNoClientId() {
        ScimUser user = new ScimUser("user-id-001", "user@example.com", "first", "last");
        user.setOrigin(UAA);
        when(mockScimUserProvisioning.retrieve(eq("user-id-001"), eq(zoneId))).thenReturn(user);
        when(mockScimUserProvisioning.verifyUser(anyString(), anyInt(), eq(zoneId))).thenReturn(user);
        doThrow(NoSuchClientException.class).when(mockClientDetailsService).loadClientByClientId(null, zoneId);

        Map<String, String> userData = new HashMap<>();
        userData.put(USER_ID, "user-id-001");
        userData.put(EMAIL, "user@example.com");
        userData.put(CLIENT_ID, null);
        when(mockExpiringCodeStore.retrieveCode(anyString(), eq(zoneId))).thenReturn(new ExpiringCode("code", new Timestamp(System.currentTimeMillis()), JsonUtils.writeValueAsString(userData), INVITATION.name()));

        String redirectLocation = emailInvitationsService.acceptInvitation("code", "password").getRedirectUri();
        verify(mockScimUserProvisioning).verifyUser(user.getId(), user.getVersion(), zoneId);
        verify(mockScimUserProvisioning).changePassword(user.getId(), null, "password", zoneId);
        assertThat(redirectLocation).isEqualTo("/home");
    }

    @Test
    void nonMatchingCodeIntent() {
        Map<String, String> userData = new HashMap<>();
        userData.put(USER_ID, "user-id-001");
        userData.put(EMAIL, "user@example.com");
        when(mockExpiringCodeStore.retrieveCode(anyString(), eq(zoneId))).thenReturn(new ExpiringCode("code", new Timestamp(System.currentTimeMillis()), JsonUtils.writeValueAsString(userData), "wrong-intent"));

        assertThatThrownBy(() -> emailInvitationsService.acceptInvitation("code", "password"))
                .isInstanceOf(HttpClientErrorException.class)
                .hasMessageContaining("400 BAD_REQUEST");
    }

    @Test
    void acceptInvitation_withoutPasswordUpdate() {
        ScimUser user = new ScimUser("user-id-001", "user@example.com", "first", "last");
        user.setOrigin(UAA);

        UaaClientDetails clientDetails = new UaaClientDetails("client-id", null, null, null, null, "http://example.com/*/");
        when(mockClientDetailsService.loadClientByClientId("acmeClientId", zoneId)).thenReturn(clientDetails);
        when(mockScimUserProvisioning.retrieve(eq("user-id-001"), eq(zoneId))).thenReturn(user);
        when(mockScimUserProvisioning.verifyUser(anyString(), anyInt(), eq(zoneId))).thenReturn(user);

        Map<String, String> userData = new HashMap<>();
        userData.put(USER_ID, "user-id-001");
        userData.put(EMAIL, "user@example.com");
        userData.put(CLIENT_ID, "acmeClientId");
        userData.put(REDIRECT_URI, "http://example.com/redirect/");
        when(mockExpiringCodeStore.retrieveCode(anyString(), eq(zoneId))).thenReturn(new ExpiringCode("code", new Timestamp(System.currentTimeMillis()), JsonUtils.writeValueAsString(userData), INVITATION.name()));

        emailInvitationsService.acceptInvitation("code", "");
        verify(mockScimUserProvisioning).verifyUser(user.getId(), user.getVersion(), zoneId);
        verify(mockScimUserProvisioning, never()).changePassword(anyString(), anyString(), anyString(), eq(zoneId));
    }

    @Test
    void acceptInvitation_onlyMarksInternalUsersAsVerified() {
        ScimUser user = new ScimUser("ldap-user-id", "ldapuser", "Charlie", "Brown");
        user.setOrigin(LDAP);

        UaaClientDetails clientDetails = new UaaClientDetails("client-id", null, null, null, null, "http://example.com/*/");
        when(mockScimUserProvisioning.retrieve(eq("ldap-user-id"), eq(zoneId))).thenReturn(user);
        when(mockClientDetailsService.loadClientByClientId("acmeClientId", zoneId)).thenReturn(clientDetails);

        Map<String, String> userData = new HashMap<>();
        userData.put(USER_ID, "ldap-user-id");
        userData.put(EMAIL, "ldapuser");
        userData.put(CLIENT_ID, "acmeClientId");
        userData.put(REDIRECT_URI, "http://example.com/redirect/");
        when(mockExpiringCodeStore.retrieveCode(anyString(), eq(zoneId))).thenReturn(new ExpiringCode("code", new Timestamp(System.currentTimeMillis()), JsonUtils.writeValueAsString(userData), INVITATION.name()));

        emailInvitationsService.acceptInvitation("code", "");

        verify(mockScimUserProvisioning, never()).verifyUser(anyString(), anyInt(), anyString());
    }

    @Test
    void acceptInvitationWithClientNotFound() {
        ScimUser user = new ScimUser("user-id-001", "user@example.com", "first", "last");
        user.setOrigin(OriginKeys.UAA);
        when(mockScimUserProvisioning.verifyUser(anyString(), anyInt(), eq(zoneId))).thenReturn(user);
        when(mockScimUserProvisioning.retrieve(eq("user-id-001"), eq(zoneId))).thenReturn(user);
        doThrow(new NoSuchClientException("Client not found")).when(mockClientDetailsService).loadClientByClientId("client-not-found", zoneId);

        Map<String, String> userData = new HashMap<>();
        userData.put(USER_ID, "user-id-001");
        userData.put(EMAIL, "user@example.com");
        userData.put(CLIENT_ID, "client-not-found");
        when(mockExpiringCodeStore.retrieveCode(anyString(), eq(zoneId))).thenReturn(new ExpiringCode("code", new Timestamp(System.currentTimeMillis()), JsonUtils.writeValueAsString(userData), INVITATION.name()));

        String redirectLocation = emailInvitationsService.acceptInvitation("code", "password").getRedirectUri();

        verify(mockScimUserProvisioning).verifyUser(user.getId(), user.getVersion(), zoneId);
        verify(mockScimUserProvisioning).changePassword(user.getId(), null, "password", zoneId);
        assertThat(redirectLocation).isEqualTo("/home");
    }

    @Test
    void acceptInvitationWithValidRedirectUri() {
        ScimUser user = new ScimUser("user-id-001", "user@example.com", "first", "last");
        user.setOrigin(UAA);
        UaaClientDetails clientDetails = new UaaClientDetails("client-id", null, null, null, null, "http://example.com/*/");
        when(mockScimUserProvisioning.retrieve(eq("user-id-001"), eq(zoneId))).thenReturn(user);
        when(mockScimUserProvisioning.verifyUser(anyString(), anyInt(), eq(zoneId))).thenReturn(user);
        when(mockClientDetailsService.loadClientByClientId("acmeClientId", zoneId)).thenReturn(clientDetails);

        Map<String, String> userData = new HashMap<>();
        userData.put(USER_ID, "user-id-001");
        userData.put(EMAIL, "user@example.com");
        userData.put(CLIENT_ID, "acmeClientId");
        userData.put(REDIRECT_URI, "http://example.com/redirect/");
        when(mockExpiringCodeStore.retrieveCode(anyString(), eq(zoneId))).thenReturn(new ExpiringCode("code", new Timestamp(System.currentTimeMillis()), JsonUtils.writeValueAsString(userData), INVITATION.name()));

        String redirectLocation = emailInvitationsService.acceptInvitation("code", "password").getRedirectUri();

        verify(mockScimUserProvisioning).verifyUser(user.getId(), user.getVersion(), zoneId);
        verify(mockScimUserProvisioning).changePassword(user.getId(), null, "password", zoneId);
        assertThat(redirectLocation).isEqualTo("http://example.com/redirect/");
    }

    @Test
    void acceptInvitationWithInvalidRedirectUri() {
        ScimUser user = new ScimUser("user-id-001", "user@example.com", "first", "last");
        user.setOrigin(UAA);
        UaaClientDetails clientDetails = new UaaClientDetails("client-id", null, null, null, null, "http://example.com/redirect");
        when(mockScimUserProvisioning.verifyUser(anyString(), anyInt(), eq(zoneId))).thenReturn(user);
        when(mockScimUserProvisioning.retrieve(eq("user-id-001"), eq(zoneId))).thenReturn(user);
        when(mockClientDetailsService.loadClientByClientId("acmeClientId", zoneId)).thenReturn(clientDetails);
        Map<String, String> userData = new HashMap<>();
        userData.put(USER_ID, "user-id-001");
        userData.put(EMAIL, "user@example.com");
        userData.put(REDIRECT_URI, "http://someother/redirect");
        userData.put(CLIENT_ID, "acmeClientId");
        when(mockExpiringCodeStore.retrieveCode(anyString(), eq(zoneId))).thenReturn(new ExpiringCode("code", new Timestamp(System.currentTimeMillis()), JsonUtils.writeValueAsString(userData), INVITATION.name()));

        String redirectLocation = emailInvitationsService.acceptInvitation("code", "password").getRedirectUri();

        verify(mockScimUserProvisioning).verifyUser(user.getId(), user.getVersion(), zoneId);
        verify(mockScimUserProvisioning).changePassword(user.getId(), null, "password", zoneId);
        assertThat(redirectLocation).isEqualTo("/home");
    }
}
