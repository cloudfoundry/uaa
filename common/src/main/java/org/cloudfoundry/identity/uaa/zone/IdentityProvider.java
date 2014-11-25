package org.cloudfoundry.identity.uaa.zone;

import java.util.UUID;

import org.springframework.jdbc.core.JdbcTemplate;

public class IdentityProvider {
    /**
     * Used for testing until we actually write the domain model
     * @param jdbcTemplate
     * @param originKey
     */
    
    public static void addIdentityProvider(JdbcTemplate jdbcTemplate, String originKey) {
        jdbcTemplate.update("insert into identity_provider (id,identity_zone_id,name,origin_key,type) values (?,'uaa',?,?,'UNKNOWN')",UUID.randomUUID().toString(),originKey,originKey);
    }

}
