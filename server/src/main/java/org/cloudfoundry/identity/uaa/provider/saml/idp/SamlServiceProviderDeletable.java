package org.cloudfoundry.identity.uaa.provider.saml.idp;

import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.slf4j.Logger;
import org.springframework.context.ApplicationListener;

/** Handles SAML service provider deleted events. */
public interface SamlServiceProviderDeletable extends ApplicationListener<EntityDeletedEvent<?>> {

  default void onApplicationEvent(EntityDeletedEvent<?> event) {
    if (event == null || event.getDeleted() == null) {
      return;
    } else if (event.getDeleted() instanceof SamlServiceProvider) {
      String entityId = ((SamlServiceProvider) event.getDeleted()).getEntityId();
      String zoneId = ((SamlServiceProvider) event.getDeleted()).getIdentityZoneId();
      deleteByEntityId(entityId, zoneId);
    } else {
      getLogger().debug("Unsupported deleted event for deletion of object:" + event.getDeleted());
    }
  }

  default boolean isUaaZone(String zoneId) {
    return IdentityZone.getUaaZoneId().equals(zoneId);
  }

  int deleteByEntityId(String entityId, String zoneId);

  int deleteByIdentityZone(String zoneId);

  Logger getLogger();
}
