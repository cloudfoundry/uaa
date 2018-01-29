package org.cloudfoundry.identity.uaa.authentication.event;

import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

public class IdentityProviderAuthenticationFailureEvent extends AbstractUaaAuthenticationEvent {

    private String username;
    private String origin;

    public String getUsername() {
        return username;
    }

    public String getOrigin() {
        return origin;
    }

    public IdentityProviderAuthenticationFailureEvent(Authentication authentication, String username, String origin) {
        super(authentication);
        this.username = username;
        this.origin = origin;
    }

    @Override
    public AuditEvent getAuditEvent() {
        Assert.notNull(username, "UaaUser cannot be null");
        return createAuditRecord(null, AuditEventType.IdentityProviderAuthenticationFailure,
                getOrigin(getAuthenticationDetails()), username);
    }
}
