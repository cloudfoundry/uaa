package org.cloudfoundry.identity.uaa.resources.jdbc;

public class MySqlLimitSqlAdapter implements LimitSqlAdapter {
    public String getDeleteExpiredQuery(String tablename, String primaryKeyColumn, String expiresColumn, int maxRows) {
        return "delete from " +
            tablename +
            " where " +
            expiresColumn +
            " < ? order by " +
            expiresColumn +
            " limit " + maxRows;
    }
}
