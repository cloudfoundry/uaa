package org.cloudfoundry.identity.uaa.resources.jdbc;

public class PostgresLimitSqlAdapter implements LimitSqlAdapter {
    @Override
    public String getDeleteExpiredQuery(String tablename, String primaryKeyColumn, String expiresColumn, int maxRows) {
        return "DELETE FROM "+
            tablename +
            " WHERE "+
            primaryKeyColumn +
            " = any (array(SELECT " +
            primaryKeyColumn +
            " FROM " +
            tablename +
            " WHERE " +
            expiresColumn +
            " < ? " +
            " ORDER BY " +
            expiresColumn +
            " LIMIT "+maxRows+"))";
    }
}
