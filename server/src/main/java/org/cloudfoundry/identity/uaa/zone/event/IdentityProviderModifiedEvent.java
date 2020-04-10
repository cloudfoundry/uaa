package org.cloudfoundry.identity.uaa.zone.event;

import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.audit.event.AbstractUaaEvent;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.springframework.security.core.Authentication;

public class IdentityProviderModifiedEvent extends AbstractUaaEvent {

  protected static final String dataFormat = "id=%s; type=%s; origin=%s; zone=%s";
  private static final long serialVersionUID = -4559543713244231262L;
  private AuditEventType eventType;

  IdentityProviderModifiedEvent(
      IdentityProvider identityProvider,
      Authentication authentication,
      AuditEventType type,
      String zoneId) {
    super(identityProvider, authentication, zoneId);
    eventType = type;
  }

  public static IdentityProviderModifiedEvent identityProviderCreated(
      IdentityProvider identityProvider, String zoneId) {
    return new IdentityProviderModifiedEvent(
        identityProvider,
        getContextAuthentication(),
        AuditEventType.IdentityProviderCreatedEvent,
        zoneId);
  }

  public static IdentityProviderModifiedEvent identityProviderModified(
      IdentityProvider identityProvider, String zoneId) {
    return new IdentityProviderModifiedEvent(
        identityProvider,
        getContextAuthentication(),
        AuditEventType.IdentityProviderModifiedEvent,
        zoneId);
  }

  @Override
  public AuditEvent getAuditEvent() {
    IdentityProvider provider = (IdentityProvider) source;
    return createAuditRecord(
        getSource().toString(),
        eventType,
        getOrigin(getAuthentication()),
        String.format(
            IdentityProviderModifiedEvent.dataFormat,
            provider.getId(),
            provider.getType(),
            provider.getOriginKey(),
            provider.getIdentityZoneId()));
  }
}
