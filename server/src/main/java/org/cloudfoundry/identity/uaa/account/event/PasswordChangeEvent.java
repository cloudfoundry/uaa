package org.cloudfoundry.identity.uaa.account.event;

import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.springframework.security.core.Authentication;

/** @author Dave Syer */
public class PasswordChangeEvent extends AbstractPasswordChangeEvent {

  public PasswordChangeEvent(
      String message, UaaUser user, Authentication principal, String zoneId) {
    super(message, user, principal, zoneId);
  }

  @Override
  public AuditEvent getAuditEvent() {
    return createAuditRecord(
        getUser().getId(),
        AuditEventType.PasswordChangeSuccess,
        getOrigin(getPrincipal()),
        getMessage());
  }
}
