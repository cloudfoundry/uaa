package org.cloudfoundry.identity.uaa.zone.event;

import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.audit.event.AbstractUaaEvent;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.security.core.Authentication;

public class IdentityZoneModifiedEvent extends AbstractUaaEvent {

  protected static final String dataFormat = "id=%s; subdomain=%s";
  private static final long serialVersionUID = 562117195472169825L;
  private AuditEventType eventType;

  public IdentityZoneModifiedEvent(
      IdentityZone identityZone,
      Authentication authentication,
      AuditEventType type,
      String zoneId) {
    super(identityZone, authentication, zoneId);
    eventType = type;
  }

  public static IdentityZoneModifiedEvent identityZoneCreated(IdentityZone identityZone) {
    return new IdentityZoneModifiedEvent(
        identityZone,
        getContextAuthentication(),
        AuditEventType.IdentityZoneCreatedEvent,
        IdentityZoneHolder.getCurrentZoneId());
  }

  public static IdentityZoneModifiedEvent identityZoneModified(IdentityZone identityZone) {
    return new IdentityZoneModifiedEvent(
        identityZone,
        getContextAuthentication(),
        AuditEventType.IdentityZoneModifiedEvent,
        IdentityZoneHolder.getCurrentZoneId());
  }

  @Override
  public AuditEvent getAuditEvent() {
    IdentityZone zone = (IdentityZone) source;
    return createAuditRecord(
        getSource().toString(),
        eventType,
        getOrigin(getAuthentication()),
        String.format(IdentityZoneModifiedEvent.dataFormat, zone.getId(), zone.getSubdomain()));
  }

  public AuditEventType getEventType() {
    return eventType;
  }
}
