package org.cloudfoundry.identity.uaa.scim.endpoints;

import org.cloudfoundry.identity.uaa.account.UserAccountStatus;
import org.cloudfoundry.identity.uaa.account.event.UserAccountUnlockedEvent;
import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEventPublisher;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ScimUserEndpointsStatusTests {

    private static final String USER_ID = "user-id";
    private static final String ZONE_ID = "zone-id";

    @Mock
    private IdentityZoneManager identityZoneManager;
    @Mock
    private ScimUserProvisioning scimUserProvisioning;
    @Mock
    private ApplicationEventPublisher publisher;

    private ScimUserEndpoints endpoints;
    private ScimUser user;

    @BeforeEach
    void setUp() {
        endpoints = new ScimUserEndpoints(identityZoneManager, null, scimUserProvisioning,
                null, null, Collections.emptyMap(), null, null, null, null, null, null, null, false, 500);
        endpoints.setApplicationEventPublisher(publisher);
        user = new ScimUser(USER_ID, "user@example.com", "Given", "Family");
        user.setZoneId(ZONE_ID);
        when(identityZoneManager.getCurrentIdentityZoneId()).thenReturn(ZONE_ID);
        when(scimUserProvisioning.retrieve(USER_ID, ZONE_ID)).thenReturn(user);
    }

    @ParameterizedTest
    @ValueSource(strings = {"uaa", "ldap", "saml-provider", "oidc-provider", "custom-provider"})
    void unlockAccountForAnyOrigin(String origin) {
        user.setOrigin(origin);
        UserAccountStatus status = new UserAccountStatus();
        status.setLocked(false);

        assertThat(endpoints.updateAccountStatus(status, USER_ID)).isSameAs(status);

        ArgumentCaptor<UserAccountUnlockedEvent> event = ArgumentCaptor.forClass(UserAccountUnlockedEvent.class);
        verify(publisher).publishEvent(event.capture());
        assertThat(event.getValue().getSource()).isSameAs(user);
        assertThat(event.getValue().getAuditEvent())
                .extracting(AuditEvent::getPrincipalId, AuditEvent::getIdentityZoneId, AuditEvent::getOrigin)
                .containsExactly(USER_ID, ZONE_ID, origin);
        verify(scimUserProvisioning).retrieve(USER_ID, ZONE_ID);
        verifyNoMoreInteractions(scimUserProvisioning);
    }

    @ParameterizedTest
    @ValueSource(strings = {"uaa", "ldap", "saml-provider", "oidc-provider", "custom-provider"})
    void emptyStatusDoesNotUnlockAccount(String origin) {
        user.setOrigin(origin);
        UserAccountStatus status = new UserAccountStatus();

        assertThat(endpoints.updateAccountStatus(status, USER_ID)).isSameAs(status);

        verifyNoInteractions(publisher);
        verify(scimUserProvisioning).retrieve(USER_ID, ZONE_ID);
        verifyNoMoreInteractions(scimUserProvisioning);
    }

    @ParameterizedTest
    @ValueSource(strings = {"uaa", "ldap", "saml-provider", "oidc-provider", "custom-provider"})
    void cannotLockAccountForAnyOrigin(String origin) {
        user.setOrigin(origin);
        UserAccountStatus status = new UserAccountStatus();
        status.setLocked(true);

        assertThatThrownBy(() -> endpoints.updateAccountStatus(status, USER_ID))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageStartingWith("Cannot set user account to locked.");

        verifyNoInteractions(publisher);
        verify(scimUserProvisioning).retrieve(USER_ID, ZONE_ID);
        verifyNoMoreInteractions(scimUserProvisioning);
    }

    @ParameterizedTest
    @CsvSource({"ldap,true", "ldap,false", "saml-provider,true", "saml-provider,false",
            "oidc-provider,true", "oidc-provider,false", "custom-provider,true", "custom-provider,false"})
    void passwordChangeForExternalAccountDoesNotUnlock(String origin, boolean passwordChangeRequired) {
        user.setOrigin(origin);
        UserAccountStatus status = new UserAccountStatus();
        status.setLocked(false);
        status.setPasswordChangeRequired(passwordChangeRequired);

        assertThatThrownBy(() -> endpoints.updateAccountStatus(status, USER_ID))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Can only manage users from the internal user store.");

        verifyNoInteractions(publisher);
        verify(scimUserProvisioning).retrieve(USER_ID, ZONE_ID);
        verifyNoMoreInteractions(scimUserProvisioning);
    }

    @Test
    void unlockAndRequirePasswordChangeForInternalAccount() {
        user.setOrigin("uaa");
        UserAccountStatus status = new UserAccountStatus();
        status.setLocked(false);
        status.setPasswordChangeRequired(true);

        assertThat(endpoints.updateAccountStatus(status, USER_ID)).isSameAs(status);

        verify(publisher).publishEvent(any(UserAccountUnlockedEvent.class));
        verify(scimUserProvisioning).updatePasswordChangeRequired(USER_ID, true, ZONE_ID);
    }

    @Test
    void cannotRemovePasswordChangeRequirementOrUnlockInternalAccount() {
        user.setOrigin("uaa");
        UserAccountStatus status = new UserAccountStatus();
        status.setLocked(false);
        status.setPasswordChangeRequired(false);

        assertThatThrownBy(() -> endpoints.updateAccountStatus(status, USER_ID))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("The requirement that this user change their password cannot be removed via API.");

        verifyNoInteractions(publisher);
        verify(scimUserProvisioning).retrieve(USER_ID, ZONE_ID);
        verifyNoMoreInteractions(scimUserProvisioning);
    }
}
