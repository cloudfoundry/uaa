package org.cloudfoundry.identity.uaa.client.event;

import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.ClientDetails;

public class SecretChangeEvent extends AbstractClientAdminEvent {

  public SecretChangeEvent(ClientDetails client, Authentication principal, String zoneId) {
    super(client, principal, zoneId);
  }

  @Override
  public AuditEventType getAuditEventType() {
    return AuditEventType.SecretChangeSuccess;
  }
}
