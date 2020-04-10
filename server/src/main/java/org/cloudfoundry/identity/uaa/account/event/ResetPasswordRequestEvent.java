package org.cloudfoundry.identity.uaa.account.event;

import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.audit.event.AbstractUaaEvent;
import org.springframework.security.core.Authentication;

public class ResetPasswordRequestEvent extends AbstractUaaEvent {

  private String code;
  private String email;

  public ResetPasswordRequestEvent(
      String username, String email, String code, Authentication authentication, String zoneId) {
    super(username, authentication, zoneId);
    this.code = code;
    this.email = email;
  }

  @Override
  public AuditEvent getAuditEvent() {
    return createAuditRecord(
        getSource().toString(),
        AuditEventType.PasswordResetRequest,
        getOrigin(getAuthentication()),
        email);
  }

  public String getCode() {
    return code;
  }

  public String getEmail() {
    return email;
  }
}
