package org.cloudfoundry.identity.uaa.resources.jdbc;

public class HsqlDbLimitSqlAdapter implements LimitSqlAdapter {

  @Override
  public String getDeleteExpiredQuery(
      String tablename, String primaryKeyColumn, String expiresColumn, int maxRows) {
    return "DELETE FROM "
        + tablename
        + " WHERE "
        + primaryKeyColumn
        + " IN "
        + "(SELECT "
        + primaryKeyColumn
        + " FROM "
        + tablename
        + " WHERE "
        + expiresColumn
        + " < ?"
        + " ORDER BY "
        + expiresColumn
        + " LIMIT "
        + maxRows
        + " OFFSET 0)";
  }
}
