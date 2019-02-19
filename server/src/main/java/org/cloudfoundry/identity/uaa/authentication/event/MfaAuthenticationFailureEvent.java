package org.cloudfoundry.identity.uaa.authentication.event;

import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

public class MfaAuthenticationFailureEvent extends AbstractUaaAuthenticationEvent {
    private final UaaUser user;
    private final String type;

    public MfaAuthenticationFailureEvent(UaaUser user, Authentication authentication, String type) {
        super(authentication);
        this.user = user;
        this.type = type;
    }

    @Override
    public AuditEvent getAuditEvent() {
        Assert.notNull(user, "UaaUser cannot be null");
        return createAuditRecord(user.getId(), AuditEventType.MfaAuthenticationFailure,
                getOrigin(getAuthenticationDetails()), user.getUsername(), type, null);
    }

    public UaaUser getUser() {
        return user;
    }
}
