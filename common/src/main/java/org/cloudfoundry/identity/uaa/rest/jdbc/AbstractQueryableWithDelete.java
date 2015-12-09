/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.rest.jdbc;

import org.apache.commons.logging.Log;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.springframework.context.ApplicationListener;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;

public abstract class AbstractQueryableWithDelete<T> extends AbstractQueryable<T> implements ApplicationListener<EntityDeletedEvent<?>> {

    protected AbstractQueryableWithDelete(JdbcTemplate jdbcTemplate, JdbcPagingListFactory pagingListFactory, RowMapper<T> rowMapper) {
        super(jdbcTemplate, pagingListFactory, rowMapper);
    }

    @Override
    public void onApplicationEvent(EntityDeletedEvent<?> event) {
        if (event==null || event.getDeleted()==null) {
            return;
        } else if (event.getDeleted() instanceof IdentityZone) {
            String zoneId = ((IdentityZone)event.getDeleted()).getId();
            if (isUaaZone(zoneId)) {
                getLogger().debug("Attempt to delete default zone ignored:"+event.getDeleted());
                return;
            }
            deleteByIdentityZone(zoneId);
        } else if (event.getDeleted() instanceof IdentityProvider) {
            String zoneId = ((IdentityProvider)event.getDeleted()).getIdentityZoneId();
            String origin = ((IdentityProvider)event.getDeleted()).getOriginKey();
            if (OriginKeys.UAA.equals(origin)) {
                getLogger().debug("Attempt to delete default UAA provider ignored:"+event.getDeleted());
                return;
            }
            deleteByOrigin(origin, zoneId);
        } else {
            getLogger().debug("Unsupported deleted event for deletion of object:"+event.getDeleted());
        }
    }

    protected boolean isUaaZone(String zoneId) {
        return IdentityZone.getUaa().getId().equals(zoneId);
    }

    protected abstract int deleteByIdentityZone(String zoneId);

    protected abstract int deleteByOrigin(String origin, String zoneId);

    protected abstract Log getLogger();
}
