/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.provider.saml.idp;

import org.slf4j.Logger;
import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.springframework.context.ApplicationListener;

/**
 * Handles SAML service provider deleted events.
 */
public interface SamlServiceProviderDeletable extends ApplicationListener<EntityDeletedEvent<?>> {
    default void onApplicationEvent(EntityDeletedEvent<?> event) {
        if (event==null || event.getDeleted()==null) {
            return;
        } else if (event.getDeleted() instanceof SamlServiceProvider) {
            String entityId = ((SamlServiceProvider)event.getDeleted()).getEntityId();
            String zoneId = ((SamlServiceProvider)event.getDeleted()).getIdentityZoneId();
            deleteByEntityId(entityId, zoneId);
        } else {
            getLogger().debug("Unsupported deleted event for deletion of object:"+event.getDeleted());
        }
    }

    default boolean isUaaZone(String zoneId) {
        return IdentityZone.getUaaZoneId().equals(zoneId);
    }

    int deleteByEntityId(String entityId, String zoneId);

    int deleteByIdentityZone(String zoneId);

    Logger getLogger();
}
