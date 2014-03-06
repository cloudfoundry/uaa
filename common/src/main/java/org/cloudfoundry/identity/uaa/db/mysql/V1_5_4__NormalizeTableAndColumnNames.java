package org.cloudfoundry.identity.uaa.db.mysql;

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

    private String colQuery = "SELECT CONCAT(\n" +
            "'ALTER TABLE ', table_name, \n" +
            "' CHANGE ', column_name, ' ', \n" +
            "LOWER(column_name), ' ', column_type, ' ', extra,\n" +
            "CASE WHEN IS_NULLABLE = 'YES' THEN  ' NULL' ELSE ' NOT NULL' END, ';') AS line, table_name, column_name \n" +
            "FROM information_schema.columns\n" +
            "WHERE table_schema = 'uaa' \n" +
            "ORDER BY line";

    @Override
    public void migrate(JdbcTemplate jdbcTemplate) throws Exception {
        logger.info("[V1_5_4] Running SQL: "+colQuery);
        List<DatabaseInformation1_5_3.ColumnInfo> columns = jdbcTemplate.query(colQuery,new DatabaseInformation1_5_3.ColumnMapper());
        for (DatabaseInformation1_5_3.ColumnInfo column : columns) {
            if (processColumn(column)) {
                String sql = column.sql;
                logger.info("Renaming column: ["+sql+"]");
                jdbcTemplate.execute(sql);
            }
        }
    }
}
