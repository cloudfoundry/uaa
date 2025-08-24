/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.audit.event;

import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.slf4j.Logger;
import org.springframework.context.ApplicationListener;

public interface SystemDeletable extends ApplicationListener<AbstractUaaEvent> {
    default void onApplicationEvent(EntityDeletedEvent<?> event) {
        if (event == null || event.getDeleted() == null) {
            return;
        }
        if (event.getDeleted() instanceof IdentityZone identityZone) {
            String zoneId = identityZone.getId();
            getLogger().debug("Received zone deletion event for id:{}", zoneId);
            if (identityZone.isUaa()) {
                getLogger().debug("Attempt to delete default zone ignored:{}", event.getDeleted());
                return;
            }
            deleteByIdentityZone(zoneId);
        } else if (event.getDeleted() instanceof IdentityProvider provider) {
            String zoneId = provider.getIdentityZoneId();
            String origin = provider.getOriginKey();
            getLogger().debug("Received provider deletion event for zone_id:{} and origin:{}", zoneId, origin);
            if (OriginKeys.UAA.equals(origin)) {
                getLogger().debug("Attempt to delete default UAA provider ignored:{}", event.getDeleted());
                return;
            }
            deleteByOrigin(origin, zoneId);
        } else if (event.getDeleted() instanceof ClientDetails) {
            String clientId = ((ClientDetails) event.getDeleted()).getClientId();
            String zoneId = event.getIdentityZoneId();
            getLogger().debug("Received client deletion event for zone_id:{} and client:{}", zoneId, clientId);
            deleteByClient(clientId, zoneId);
        } else if (event.getDeleted() instanceof UaaUser) {
            String userId = ((UaaUser) event.getDeleted()).getId();
            String zoneId = ((UaaUser) event.getDeleted()).getZoneId();
            getLogger().debug("Received UAA user deletion event for zone_id:{} and user:{}", zoneId, userId);
            deleteByUser(userId, zoneId);
        } else if (event.getDeleted() instanceof ScimUser) {
            String userId = ((ScimUser) event.getDeleted()).getId();
            String zoneId = ((ScimUser) event.getDeleted()).getZoneId();
            getLogger().debug("Received SCIM user deletion event for zone_id:{} and user:{}", zoneId, userId);
            deleteByUser(userId, zoneId);
        } else {
            getLogger().debug("Unsupported deleted event for deletion of object:{}", event.getDeleted());
        }
    }

    default void onApplicationEvent(AbstractUaaEvent event) {
        if (event instanceof EntityDeletedEvent deletedEvent) {
            onApplicationEvent(deletedEvent);
        }
    }

    default int deleteByIdentityZone(String zoneId) {
        return 0;
    }

    default int deleteByOrigin(String origin, String zoneId) {
        return 0;
    }

    default int deleteByClient(String clientId, String zoneId) {
        return 0;
    }

    default int deleteByUser(String userId, String zoneId) {
        return 0;
    }

    Logger getLogger();
}
