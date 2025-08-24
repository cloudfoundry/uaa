/*
 * *****************************************************************************
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

import org.flywaydb.core.api.migration.BaseJavaMigration;
import org.flywaydb.core.api.migration.Context;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;

import static org.cloudfoundry.identity.uaa.db.DatabaseInformation1_5_3.*;


/**
 * Created by fhanik on 3/5/14.
 */
public class V1_5_4__NormalizeTableAndColumnNames extends BaseJavaMigration {

    private final Logger logger = LoggerFactory.getLogger(getClass());

    private final String colQuery = """
            SELECT 'noop',\s
              c.relname as table_name,
              a.attname as column_name\s
            FROM pg_catalog.pg_class c
                 LEFT JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                 LEFT JOIN pg_catalog.pg_attribute a ON a.attrelid = c.relname::regclass   \s
            WHERE
                   n.nspname <> 'pg_catalog'
                  AND n.nspname <> 'information_schema'
                  AND n.nspname !~ '^pg_toast'
              AND pg_catalog.pg_table_is_visible(c.oid)
              AND c.relkind = 'r'
              AND a.attnum > 0
            ORDER BY 1,2""";

    @Override
    public void migrate(Context context) {
        logger.info("[V1_5_4] Running SQL: {}", colQuery);
        JdbcTemplate jdbcTemplate = new JdbcTemplate(new SingleConnectionDataSource(
                context.getConnection(), true));
        List<ColumnInfo> columns = jdbcTemplate.query(colQuery, new ColumnMapper());
        for (ColumnInfo column : columns) {
            if (processColumn(column)) {
                String sql = "ALTER TABLE " + column.tableName + " RENAME \"" + column.columnName + "\" TO \""
                        + column.columnName.toLowerCase() + "\"";
                logger.info("Renaming column: [{}]", sql);
                jdbcTemplate.execute(sql);
            }
        }
    }

}
