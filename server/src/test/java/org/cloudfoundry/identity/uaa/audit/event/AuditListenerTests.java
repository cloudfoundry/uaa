package org.cloudfoundry.identity.uaa.audit.event;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;


import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.UaaAuditService;
import org.cloudfoundry.identity.uaa.authentication.event.UserAuthenticationFailureEvent;
import org.cloudfoundry.identity.uaa.authentication.event.UserAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.authentication.event.UserNotFoundEvent;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;

@ExtendWith(PollutionPreventionExtension.class)
@ExtendWith(MockitoExtension.class)
class AuditListenerTests {

    @Mock
    private UaaAuditService mockUaaAuditService;

    @Mock
    private UaaUser mockUser;

    @Mock
    private Authentication mockAuthentication;

    @InjectMocks
    private AuditListener auditListener;

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
