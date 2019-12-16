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
package org.cloudfoundry.identity.uaa.db.mysql;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.cloudfoundry.identity.uaa.db.DatabaseInformation1_5_3;
import org.flywaydb.core.api.migration.spring.SpringJdbcMigration;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.List;


/**
 * Created by fhanik on 3/5/14.
 */
public class V1_5_4__NormalizeTableAndColumnNames extends DatabaseInformation1_5_3 implements SpringJdbcMigration {

    private final Logger logger = LoggerFactory.getLogger(getClass());

    private String colQuery = "SELECT CONCAT(\n"
                    +
                    "'ALTER TABLE ', table_name, \n"
                    +
                    "' CHANGE ', column_name, ' ', \n"
                    +
                    "LOWER(column_name), ' ', column_type, ' ', extra,\n"
                    +
                    "CASE WHEN IS_NULLABLE = 'YES' THEN  ' NULL' ELSE ' NOT NULL' END, IF(column_default IS NULL, '', CONCAT(' DEFAULT ',column_default)), ';') AS line, table_name, column_name \n"
                    +
                    "FROM information_schema.columns\n" +
                    "WHERE table_schema = 'uaa' \n" +
                    "ORDER BY line";

    @Override
    public void migrate(JdbcTemplate jdbcTemplate) {
        logger.info("[V1_5_4] Running SQL: " + colQuery);
        List<DatabaseInformation1_5_3.ColumnInfo> columns = jdbcTemplate.query(colQuery,
                        new DatabaseInformation1_5_3.ColumnMapper());
        for (DatabaseInformation1_5_3.ColumnInfo column : columns) {
            if (processColumn(column)) {
                String sql = column.sql.replaceAll("2001-01-01 .*", "'2001-01-01 01:01:01.000001'");
                logger.info("Renaming column: [" + sql + "]");
                jdbcTemplate.execute(sql);
            }
        }
    }
}
