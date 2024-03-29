package org.cloudfoundry.identity.uaa.db.mysql;

import org.flywaydb.core.api.migration.BaseJavaMigration;
import org.flywaydb.core.api.migration.Context;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;


public class V4_9_2__AddPrimaryKeysIfMissing extends BaseJavaMigration {

    private final String checkPrimaryKeyExists = "SELECT COUNT(*) FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? AND CONSTRAINT_NAME = 'PRIMARY'";

    @Override
    public void migrate(Context context) throws Exception {
        String[] tables = {"group_membership", "external_group_mapping", "oauth_code", "sec_audit"};
        JdbcTemplate jdbcTemplate = new JdbcTemplate(new SingleConnectionDataSource(
                context.getConnection(), true));
        for (String table : tables) {
            int count = jdbcTemplate.queryForObject(checkPrimaryKeyExists, Integer.class, jdbcTemplate.getDataSource().getConnection().getCatalog(), table);
            if (count == 0) {
                String sql = "ALTER TABLE " + table + " ADD COLUMN `id` int(11) unsigned PRIMARY KEY AUTO_INCREMENT";
                jdbcTemplate.execute(sql);
            }
        }
    }
}