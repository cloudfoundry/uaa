package org.cloudfoundry.identity.uaa.db.mysql;

import org.flywaydb.core.api.migration.spring.SpringJdbcMigration;
import org.springframework.jdbc.core.JdbcTemplate;

import java.sql.Connection;
import java.sql.SQLException;

public class V4_9_2__AddPrimaryKeysIfMissing implements SpringJdbcMigration {

    private final String checkPrimaryKeyExists = "SELECT COUNT(*) FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? AND CONSTRAINT_NAME = 'PRIMARY'";

    @Override
    public void migrate(JdbcTemplate jdbcTemplate) throws Exception {
        String[] tables = {"group_membership", "external_group_mapping", "oauth_code", "sec_audit"};
        String catalogName;
        try(Connection connection = jdbcTemplate.getDataSource().getConnection()) {
            catalogName = connection.getCatalog();
        } catch (Exception e) {
            throw e;
        }
        for (String table : tables) {
            int count = jdbcTemplate.queryForObject(checkPrimaryKeyExists, Integer.class, catalogName, table);
            if (count == 0) {
                String sql = "ALTER TABLE " + table + " ADD COLUMN `id` int(11) unsigned PRIMARY KEY AUTO_INCREMENT";
                jdbcTemplate.execute(sql);
            }
        }
    }
}