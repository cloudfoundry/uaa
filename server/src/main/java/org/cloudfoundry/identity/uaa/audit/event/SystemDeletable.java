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

import org.apache.commons.logging.Log;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.context.ApplicationListener;
import org.springframework.security.oauth2.provider.ClientDetails;

public interface SystemDeletable extends ApplicationListener<AbstractUaaEvent> {
    default void onApplicationEvent(EntityDeletedEvent<?> event) {
        if (event==null || event.getDeleted()==null) {
            return;
        } else if (event.getDeleted() instanceof IdentityZone) {
            String zoneId = ((IdentityZone)event.getDeleted()).getId();
            getLogger().debug(String.format("Received zone deletion event for id:%s", zoneId));
            if (isUaaZone(zoneId)) {
                getLogger().debug("Attempt to delete default zone ignored:"+event.getDeleted());
                return;
            }
            deleteByIdentityZone(zoneId);
        } else if (event.getDeleted() instanceof IdentityProvider) {
            String zoneId = ((IdentityProvider)event.getDeleted()).getIdentityZoneId();
            String origin = ((IdentityProvider)event.getDeleted()).getOriginKey();
            getLogger().debug(String.format("Received provider deletion event for zone_id:%s and origin:%s", zoneId, origin));
            if (OriginKeys.UAA.equals(origin)) {
                getLogger().debug("Attempt to delete default UAA provider ignored:"+event.getDeleted());
                return;
            }
            deleteByOrigin(origin, zoneId);
        } else if (event.getDeleted() instanceof ClientDetails) {
            String clientId = ((ClientDetails) event.getDeleted()).getClientId();
            String zoneId = IdentityZoneHolder.get().getId();
            getLogger().debug(String.format("Received client deletion event for zone_id:%s and client:%s", zoneId, clientId));
            deleteByClient(clientId, zoneId);
        } else if (event.getDeleted() instanceof UaaUser) {
            String userId = ((UaaUser) event.getDeleted()).getId();
            String zoneId = ((UaaUser) event.getDeleted()).getZoneId();
            getLogger().debug(String.format("Received UAA user deletion event for zone_id:%s and user:%s", zoneId, userId));
            deleteByUser(userId, zoneId);
        } else if (event.getDeleted() instanceof ScimUser) {
            String userId = ((ScimUser) event.getDeleted()).getId();
            String zoneId = ((ScimUser) event.getDeleted()).getZoneId();
            getLogger().debug(String.format("Received SCIM user deletion event for zone_id:%s and user:%s", zoneId, userId));
            deleteByUser(userId, zoneId);
        } else {
            getLogger().debug("Unsupported deleted event for deletion of object:"+event.getDeleted());
        }
    }

    default void onApplicationEvent(AbstractUaaEvent event) {
        if (event instanceof EntityDeletedEvent) {
            onApplicationEvent((EntityDeletedEvent)event);
        }
    }

    default boolean isUaaZone(String zoneId) {
        return IdentityZone.getUaa().getId().equals(zoneId);
    }

    int deleteByIdentityZone(String zoneId);

    int deleteByOrigin(String origin, String zoneId);

    int deleteByClient(String clientId, String zoneId);

    int deleteByUser(String userId, String zoneId);

    Log getLogger();
}
