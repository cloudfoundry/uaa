package org.cloudfoundry.identity.uaa.authentication.event;

import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

public class UnverifiedUserAuthenticationEvent extends AbstractUaaAuthenticationEvent {

    private final UaaUser user;

    public UnverifiedUserAuthenticationEvent(UaaUser user, Authentication authentication, String zoneId) {
        super(authentication, zoneId);
        Assert.notNull(user, "UaaUser object cannot be null");
        this.user = user;
    }

    @Override
    public AuditEvent getAuditEvent() {
        return createAuditRecord(user.getId(), AuditEventType.UnverifiedUserAuthentication, getOrigin(getAuthenticationDetails()),
                user.getUsername());
    }

    public UaaUser getUser() {
        return user;
    }
}
