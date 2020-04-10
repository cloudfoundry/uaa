package org.cloudfoundry.identity.uaa.db;

import org.flywaydb.core.api.migration.spring.SpringJdbcMigration;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * Created by fhanik on 7/15/15.
 */
public class MigrateGroupZones_2_4_2 implements SpringJdbcMigration {

    @Override
    public void migrate(JdbcTemplate jdbcTemplate) {

    }
}
