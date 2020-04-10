package org.cloudfoundry.identity.uaa.authentication.event;

import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

public class ClientAuthenticationFailureEvent extends AbstractUaaAuthenticationEvent {

  private String clientId;
  private AuthenticationException ex;

  public ClientAuthenticationFailureEvent(
      Authentication authentication, AuthenticationException ex, String zoneId) {
    super(authentication, zoneId);
    clientId = getAuthenticationDetails().getClientId();
    this.ex = ex;
  }

  @Override
  public AuditEvent getAuditEvent() {
    return createAuditRecord(
        clientId,
        AuditEventType.ClientAuthenticationFailure,
        getOrigin(getAuthenticationDetails()),
        ex.getMessage());
  }

  public String getClientId() {
    return clientId;
  }
}
