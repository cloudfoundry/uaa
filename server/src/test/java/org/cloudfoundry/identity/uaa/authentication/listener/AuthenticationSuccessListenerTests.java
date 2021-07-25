package org.cloudfoundry.identity.uaa.authentication.listener;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.event.IdentityProviderAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.authentication.event.MfaAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.authentication.event.UserAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.mfa.MfaChecker;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.context.ApplicationEventPublisher;

import static org.mockito.Mockito.*;

class AuthenticationSuccessListenerTests {

    private AuthenticationSuccessListener listener;
    private ScimUserProvisioning mockScimUserProvisioning;
    private UaaAuthentication mockUaaAuthentication;
    private MfaChecker mockMfaChecker;
    private ApplicationEventPublisher mockApplicationEventPublisher;
    private String id;
    private UaaUserPrototype userPrototype;
    private UaaUser user;

    @BeforeEach
    void setUp() {
        mockUaaAuthentication = mock(UaaAuthentication.class);
        mockApplicationEventPublisher = mock(ApplicationEventPublisher.class);
        mockMfaChecker = mock(MfaChecker.class);
        mockScimUserProvisioning = mock(ScimUserProvisioning.class);
        listener = new AuthenticationSuccessListener(mockScimUserProvisioning, mockMfaChecker);
        listener.setApplicationEventPublisher(mockApplicationEventPublisher);
        id = "user-id";
        userPrototype = new UaaUserPrototype()
                .withId(id)
                .withUsername("testUser")
                .withEmail("test@email.com");
        user = new UaaUser(userPrototype);
    }

    private ScimUser getScimUser(UaaUser user) {
        ScimUser scimUser = new ScimUser(user.getId(), user.getUsername(), user.getGivenName(), user.getFamilyName());
        scimUser.setVerified(user.isVerified());
        return scimUser;
    }

    @Test
    void unverifiedUserBecomesVerifiedIfTheyHaveLegacyFlag() {
        userPrototype
                .withVerified(false)
                .withLegacyVerificationBehavior(true);
        UserAuthenticationSuccessEvent event = getEvent();
        final String zoneId = event.getIdentityZoneId();
        when(mockScimUserProvisioning.retrieve(id, zoneId)).thenReturn(getScimUser(event.getUser()));
        listener.onApplicationEvent(event);
        verify(mockScimUserProvisioning).verifyUser(eq(id), eq(-1), eq(zoneId));
    }

    @Test
    void unverifiedUserDoesNotBecomeVerifiedIfTheyHaveNoLegacyFlag() {
        userPrototype.withVerified(false);
        UserAuthenticationSuccessEvent event = getEvent();
        final String zoneId = event.getIdentityZoneId();
        when(mockScimUserProvisioning.retrieve(id, zoneId)).thenReturn(getScimUser(event.getUser()));
        listener.onApplicationEvent(event);
        verify(mockScimUserProvisioning, never()).verifyUser(anyString(), anyInt(), eq(zoneId));
    }

    @Test
    void userLastUpdatedGetsCalledOnEvent() {
        UserAuthenticationSuccessEvent event = getEvent();
        final String zoneId = event.getIdentityZoneId();

        when(mockScimUserProvisioning.retrieve(id, zoneId)).thenReturn(getScimUser(event.getUser()));
        listener.onApplicationEvent(event);
        verify(mockScimUserProvisioning, times(1)).updateLastLogonTime(id, zoneId);
    }

    @Test
    void previousLoginIsSetOnTheAuthentication() {
        userPrototype
                .withLastLogonSuccess(123456789L);
        UserAuthenticationSuccessEvent event = getEvent();
        final String zoneId = event.getIdentityZoneId();
        when(mockScimUserProvisioning.retrieve(this.id, zoneId)).thenReturn(getScimUser(event.getUser()));
        UaaAuthentication authentication = (UaaAuthentication) event.getAuthentication();
        listener.onApplicationEvent(event);
        verify(authentication).setLastLoginSuccessTime(123456789L);
    }

    @Test
    void provider_authentication_success_triggers_user_authentication_success() {
        when(mockMfaChecker.isMfaEnabledForZoneId(anyString())).thenReturn(false);
        IdentityProviderAuthenticationSuccessEvent event = new IdentityProviderAuthenticationSuccessEvent(
                user,
                mockUaaAuthentication,
                OriginKeys.UAA, IdentityZoneHolder.getCurrentZoneId()
        );
        listener.onApplicationEvent(event);
        verify(mockApplicationEventPublisher, times(1)).publishEvent(isA(UserAuthenticationSuccessEvent.class));
    }

    @Test
    void provider_authentication_success_does_not_trigger_user_authentication_success() {
        when(mockMfaChecker.isMfaEnabledForZoneId(anyString())).thenReturn(true);
        IdentityProviderAuthenticationSuccessEvent event = new IdentityProviderAuthenticationSuccessEvent(
                user,
                mockUaaAuthentication,
                OriginKeys.UAA, IdentityZoneHolder.getCurrentZoneId()
        );
        listener.onApplicationEvent(event);
        verifyZeroInteractions(mockApplicationEventPublisher);
    }

    @Test
    void mfa_authentication_success_triggers_user_authentication_success() {
        MfaAuthenticationSuccessEvent event = new MfaAuthenticationSuccessEvent(
                user,
                mockUaaAuthentication,
                "mfa-type", IdentityZoneHolder.getCurrentZoneId()
        );
        listener.onApplicationEvent(event);
        verify(mockApplicationEventPublisher, times(1)).publishEvent(isA(UserAuthenticationSuccessEvent.class));
    }

    private UserAuthenticationSuccessEvent getEvent() {
        user = new UaaUser(userPrototype);
        return new UserAuthenticationSuccessEvent(user, mockUaaAuthentication, IdentityZoneHolder.getCurrentZoneId());
    }

}
