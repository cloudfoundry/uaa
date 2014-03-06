package org.cloudfoundry.identity.uaa.db.postgresql;

import com.googlecode.flyway.core.api.migration.spring.SpringJdbcMigration;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.db.DatabaseInformation1_5_3;

import org.springframework.jdbc.core.JdbcTemplate;
import java.util.List;

/**
 * Created by fhanik on 3/5/14.
 */
public class V1_5_4__NormalizeTableAndColumnNames extends DatabaseInformation1_5_3 implements SpringJdbcMigration {

    private final Log logger = LogFactory.getLog(getClass());

    private String colQuery = "SELECT 'noop', \n" +
            "  c.relname as table_name,\n" +
            "  a.attname as column_name \n" +
            "FROM pg_catalog.pg_class c\n" +
            "     LEFT JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace\n" +
            "     LEFT JOIN pg_catalog.pg_attribute a ON a.attrelid = c.relname::regclass    \n" +
            "WHERE\n" +
            "       n.nspname <> 'pg_catalog'\n" +
            "      AND n.nspname <> 'information_schema'\n" +
            "      AND n.nspname !~ '^pg_toast'\n" +
            "  AND pg_catalog.pg_table_is_visible(c.oid)\n" +
            "  AND c.relkind = 'r'\n" +
            "  AND a.attnum > 0\n" +
            "ORDER BY 1,2";

    @Override
    public void migrate(JdbcTemplate jdbcTemplate) throws Exception {
        logger.info("[V1_5_4] Running SQL: "+colQuery);
        List<ColumnInfo> columns = jdbcTemplate.query(colQuery,new ColumnMapper());
        for (ColumnInfo column : columns) {
            if (processColumn(column)) {
                String sql = "ALTER TABLE " + column.tableName + " RENAME " + column.columnName + " TO " + column.columnName.toLowerCase();
                logger.info("Renaming column: ["+sql+"]");
                jdbcTemplate.execute(sql);
            }
        }
    }


}
