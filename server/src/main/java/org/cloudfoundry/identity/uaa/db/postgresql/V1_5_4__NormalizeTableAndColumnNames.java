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
package org.cloudfoundry.identity.uaa.db.postgresql;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.cloudfoundry.identity.uaa.db.DatabaseInformation1_5_3;
import org.flywaydb.core.api.migration.spring.SpringJdbcMigration;
import org.springframework.jdbc.core.JdbcTemplate;



/**
 * Created by fhanik on 3/5/14.
 */
public class V1_5_4__NormalizeTableAndColumnNames extends DatabaseInformation1_5_3 implements SpringJdbcMigration {

    private final Logger logger = LoggerFactory.getLogger(getClass());

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
    public void migrate(JdbcTemplate jdbcTemplate) {
        logger.info("[V1_5_4] Running SQL: " + colQuery);
        List<ColumnInfo> columns = jdbcTemplate.query(colQuery, new ColumnMapper());
        for (ColumnInfo column : columns) {
            if (processColumn(column)) {
                String sql = "ALTER TABLE " + column.tableName + " RENAME \"" + column.columnName + "\" TO \""
                                + column.columnName.toLowerCase() + "\"";
                logger.info("Renaming column: [" + sql + "]");
                jdbcTemplate.execute(sql);
            }
        }
    }

}
