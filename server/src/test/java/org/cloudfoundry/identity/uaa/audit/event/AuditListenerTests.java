package org.cloudfoundry.identity.uaa.audit.event;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import javax.servlet.http.HttpServletRequest;
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

    private AuditListener listener;
    private UaaAuditService auditor;
    private UaaUser user = new UaaUser("auser", "password", "auser@blah.com", "A", "User");
    private UaaAuthenticationDetails details;

    @BeforeEach
    void setUp() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        details = new UaaAuthenticationDetails(request);
        auditor = mock(UaaAuditService.class);
        listener = new AuditListener(auditor);
    }

    @Test
    void userNotFoundIsAudited() {
        AuthzAuthenticationRequest req = new AuthzAuthenticationRequest("breakin", "password", details);
        listener.onApplicationEvent(new UserNotFoundEvent(req, IdentityZoneHolder.getCurrentZoneId()));
        verify(auditor).log(isA(AuditEvent.class), eq(IdentityZoneHolder.get().getId()));
    }

    @Test
    void successfulUserAuthenticationIsAudited() {
        listener.onApplicationEvent(new UserAuthenticationSuccessEvent(user, mock(Authentication.class), IdentityZoneHolder.getCurrentZoneId()));
        verify(auditor).log(isA(AuditEvent.class), eq(IdentityZoneHolder.get().getId()));
    }

    @Test
    void unsuccessfulUserAuthenticationIsAudited() {
        AuthzAuthenticationRequest req = new AuthzAuthenticationRequest("auser", "password", details);
        listener.onApplicationEvent(new UserAuthenticationFailureEvent(user, req, IdentityZoneHolder.getCurrentZoneId()));
        verify(auditor).log(isA(AuditEvent.class), eq(IdentityZoneHolder.get().getId()));
    }

}
