package org.cloudfoundry.identity.uaa.authentication.event;

import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

public class IdentityProviderAuthenticationFailureEvent extends AbstractUaaAuthenticationEvent {
    private final UaaUser user;

    public IdentityProviderAuthenticationFailureEvent(UaaUser user, Authentication authentication) {
        super(authentication);
        this.user = user;
    }

    @Override
    public AuditEvent getAuditEvent() {
        Assert.notNull(user, "UaaUser cannot be null");
        return createAuditRecord(user.getId(), AuditEventType.IdentityProviderAuthenticationFailure,
                getOrigin(getAuthenticationDetails()), user.getUsername());
    }

    public UaaUser getUser() {
        return user;
    }
}
