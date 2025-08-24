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
package org.cloudfoundry.identity.uaa.db.mysql;

import org.cloudfoundry.identity.uaa.util.beans.DbUtils;
import org.flywaydb.core.api.migration.BaseJavaMigration;
import org.flywaydb.core.api.migration.Context;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;
import org.springframework.jdbc.support.MetaDataAccessException;

import java.sql.SQLException;
import java.util.List;

import static org.cloudfoundry.identity.uaa.db.DatabaseInformation1_5_3.*;

/**
 * Created by fhanik on 3/5/14.
 */
public class V1_5_4__NormalizeTableAndColumnNames extends BaseJavaMigration {

    private final Logger logger = LoggerFactory.getLogger(getClass());

    // the system table `information_schema.columns` has columns like: table_name, column_name, column_type, extra, column_default, table_schema
    private final String colQueryForMysql5 = """
            SELECT CONCAT(
            'ALTER TABLE ', table_name,\s
            ' CHANGE ', column_name, ' ',\s
            LOWER(column_name), ' ', column_type, ' ', extra,
            CASE WHEN IS_NULLABLE = 'YES' THEN  ' NULL' ELSE ' NOT NULL' END, IF(column_default IS NULL, '', CONCAT(' DEFAULT ',column_default)), ';') AS line, table_name, column_name\s
            FROM information_schema.columns
            WHERE table_schema = 'uaa'\s
            ORDER BY line""";

    private final String colQueryTemplateForMysql8 = """
            SELECT CONCAT(
            'ALTER TABLE `', table_name, '`'\s
            ' RENAME COLUMN ', column_name, ' TO ',\s
            LOWER(column_name),
            ';') AS line, table_name, column_name\s
            FROM information_schema.columns
            WHERE table_schema = 'uaa'\s
            ORDER BY line""";

    @Override
    public void migrate(Context context) throws MetaDataAccessException, SQLException {
        JdbcTemplate jdbcTemplate = new JdbcTemplate(new SingleConnectionDataSource(
                context.getConnection(), true));

        List<ColumnInfo> columns;
        if (DbUtils.getDatabaseMajorVersion(jdbcTemplate) < 8) {
            logger.info("[V1_5_4] Running SQL: {}", colQueryForMysql5);
            columns = jdbcTemplate.query(colQueryForMysql5, new ColumnMapper());
        } else {
            logger.info("[V1_5_4] Running SQL: {}", colQueryTemplateForMysql8);
            columns = jdbcTemplate.query(colQueryTemplateForMysql8, new ColumnMapper());
        }

        for (ColumnInfo column : columns) {
            if (processColumn(column)) {
                String sql = column.sql.replaceAll("2001-01-01 .*", "'2001-01-01 01:01:01.000001'");
                logger.info("Renaming column: [{}]", sql);
                jdbcTemplate.execute(sql);
            }
        }
    }
}
