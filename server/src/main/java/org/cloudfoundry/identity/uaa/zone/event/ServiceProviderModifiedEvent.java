package org.cloudfoundry.identity.uaa.zone.event;

import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.audit.event.AbstractUaaEvent;
import org.cloudfoundry.identity.uaa.provider.saml.idp.SamlServiceProvider;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.security.core.Authentication;

public class ServiceProviderModifiedEvent extends AbstractUaaEvent {

  protected static final String dataFormat = "id=%s; name=%s; entityID=%s";
  private static final long serialVersionUID = -204120790766086570L;
  private AuditEventType eventType;

  public ServiceProviderModifiedEvent(
      SamlServiceProvider serviceProvider,
      Authentication authentication,
      AuditEventType type,
      String zoneId) {
    super(serviceProvider, authentication, zoneId);
    eventType = type;
  }

  public static ServiceProviderModifiedEvent serviceProviderCreated(
      SamlServiceProvider serviceProvider) {
    return new ServiceProviderModifiedEvent(
        serviceProvider,
        getContextAuthentication(),
        AuditEventType.ServiceProviderCreatedEvent,
        IdentityZoneHolder.getCurrentZoneId());
  }

  public static ServiceProviderModifiedEvent serviceProviderModified(
      SamlServiceProvider serviceProvider) {
    return new ServiceProviderModifiedEvent(
        serviceProvider,
        getContextAuthentication(),
        AuditEventType.ServiceProviderModifiedEvent,
        IdentityZoneHolder.getCurrentZoneId());
  }

  @Override
  public AuditEvent getAuditEvent() {
    SamlServiceProvider provider = (SamlServiceProvider) source;
    return createAuditRecord(
        getSource().toString(),
        eventType,
        getOrigin(getAuthentication()),
        String.format(dataFormat, provider.getId(), provider.getName(), provider.getEntityId()));
  }
}
