package org.cloudfoundry.identity.uaa.client.event;

import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.ClientDetails;

public class SecretFailureEvent extends AbstractClientAdminEvent {

  private String message;

  public SecretFailureEvent(String message, Authentication principal) {
    this(message, null, principal, IdentityZoneHolder.getCurrentZoneId());
  }

  public SecretFailureEvent(
      String message, ClientDetails client, Authentication principal, String zoneId) {
    super(client, principal, zoneId);
    this.message = message;
  }

  @Override
  public AuditEventType getAuditEventType() {
    return (getClient() == null)
        ? AuditEventType.SecretChangeFailure
        : AuditEventType.SecretChangeFailure;
  }
}
