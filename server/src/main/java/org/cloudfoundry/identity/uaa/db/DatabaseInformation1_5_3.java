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
package org.cloudfoundry.identity.uaa.db;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.springframework.jdbc.core.RowMapper;

/**
 * Created by fhanik on 3/5/14.
 */
public class DatabaseInformation1_5_3 {

    public static List<String> tableNames = Collections.unmodifiableList(Arrays.asList(
            "users",
            "sec_audit",
            "oauth_client_details",
            "groups",
            "group_membership",
            "oauth_code",
            "authz_approvals",
            "external_group_mapping"

    ));

    public static boolean processColumn(ColumnInfo column) {
        return (!column.columnName.equals(column.columnName.toLowerCase())) &&
                tableNames.contains(column.tableName.toLowerCase());
    }

    public static class ColumnMapper implements RowMapper<DatabaseInformation1_5_3.ColumnInfo> {
        @Override
        public DatabaseInformation1_5_3.ColumnInfo mapRow(ResultSet rs, int rowNum) throws SQLException {
            return new DatabaseInformation1_5_3.ColumnInfo(rs.getString(1), rs.getString(2), rs.getString(3));
        }
    }

    public static class ColumnInfo {
        public String sql;
        public String tableName;
        public String columnName;

        public ColumnInfo(String sql, String tableName, String columnName) {
            this.sql = sql;
            this.columnName = columnName;
            this.tableName = tableName;
        }
    }

}
