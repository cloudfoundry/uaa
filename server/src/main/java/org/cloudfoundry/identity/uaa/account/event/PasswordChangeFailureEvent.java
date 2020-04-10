

package org.cloudfoundry.identity.uaa.account.event;

import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.springframework.security.core.Authentication;

/**
 * @author Dave Syer
 * 
 */
public class PasswordChangeFailureEvent extends AbstractPasswordChangeEvent {

    public PasswordChangeFailureEvent(String message, UaaUser user, Authentication principal, String zoneId) {
        super(message, user, principal, zoneId);
    }

    @Override
    public AuditEvent getAuditEvent() {
        UaaUser user = getUser();
        if (user == null) {
            return createAuditRecord(getPrincipal().getName(), AuditEventType.PasswordChangeFailure,
                            getOrigin(getPrincipal()), getMessage());
        }
        else {
            return createAuditRecord(user.getUsername(), AuditEventType.PasswordChangeFailure,
                            getOrigin(getPrincipal()), getMessage());
        }
    }

}
