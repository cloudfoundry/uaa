
package org.cloudfoundry.identity.uaa.authentication.event;

import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

/**
 * @author Luke Taylor
 * @author Dave Syer
 */
public class UserAuthenticationSuccessEvent extends AbstractUaaAuthenticationEvent {
    private final UaaUser user;

    public UserAuthenticationSuccessEvent(UaaUser user, Authentication authentication, String zoneId) {
        super(authentication, zoneId);
        this.user = user;
    }

    @Override
    public AuditEvent getAuditEvent() {
        Assert.notNull(user, "UaaUser cannot be null");
        return createAuditRecord(user.getId(), AuditEventType.UserAuthenticationSuccess,
                        getOrigin(getAuthenticationDetails()), user.getUsername());
    }

    public UaaUser getUser() {
        return user;
    }
}
