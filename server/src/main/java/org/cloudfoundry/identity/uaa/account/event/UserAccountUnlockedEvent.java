package org.cloudfoundry.identity.uaa.account.event;

import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.audit.event.AbstractUaaEvent;
import org.cloudfoundry.identity.uaa.scim.ScimUser;

public class UserAccountUnlockedEvent extends AbstractUaaEvent {
    public UserAccountUnlockedEvent(ScimUser user, String zoneId) {
        super(user, zoneId);
    }

    @Override
    public AuditEvent getAuditEvent() {
        return createAuditRecord(((ScimUser) source).getId(), AuditEventType.UserAccountUnlockedEvent, ((ScimUser) source).getOrigin());
    }
}
