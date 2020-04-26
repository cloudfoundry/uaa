package org.cloudfoundry.identity.uaa.audit.event;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;


import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.UaaAuditService;
import org.cloudfoundry.identity.uaa.authentication.AuthzAuthenticationRequest;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.event.UserAuthenticationFailureEvent;
import org.cloudfoundry.identity.uaa.authentication.event.UserAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.authentication.event.UserNotFoundEvent;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;

class AuditListenerTests {

    private UaaAuditService mockUaaAuditService;
    private UaaUser mockUser;
    private Authentication mockAuthentication;
    private AuditListener auditListener;

    @BeforeEach
    void setUp() {
        mockAuthentication = mock(Authentication.class);

        mockUser = mock(UaaUser.class);
        mockUaaAuditService = mock(UaaAuditService.class);
        auditListener = new AuditListener(mockUaaAuditService);
    }

    @Test
    void userNotFoundIsAudited() {
        when(mockAuthentication.getName()).thenReturn("name");
        auditListener.onApplicationEvent(new UserNotFoundEvent(mockAuthentication, IdentityZoneHolder.getCurrentZoneId()));
        verify(mockUaaAuditService).log(isA(AuditEvent.class), eq(IdentityZoneHolder.get().getId()));
    }

    @Test
    void successfulUserAuthenticationIsAudited() {
        auditListener.onApplicationEvent(new UserAuthenticationSuccessEvent(mockUser, mockAuthentication, IdentityZoneHolder.getCurrentZoneId()));
        verify(mockUaaAuditService).log(isA(AuditEvent.class), eq(IdentityZoneHolder.get().getId()));
    }

    @Test
    void unsuccessfulUserAuthenticationIsAudited() {
        auditListener.onApplicationEvent(new UserAuthenticationFailureEvent(mockUser, mockAuthentication, IdentityZoneHolder.getCurrentZoneId()));
        verify(mockUaaAuditService).log(isA(AuditEvent.class), eq(IdentityZoneHolder.get().getId()));
    }

}
