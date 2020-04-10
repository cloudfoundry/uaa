package org.cloudfoundry.identity.uaa.resources.jdbc;

public interface LimitSqlAdapter {

  default String getLimitSql(String sql, int index, int size) {
    return sql + " limit " + size + " offset " + index;
  }

  String getDeleteExpiredQuery(
      String tablename, String primaryKeyColumn, String expiresColumn, int maxRows);
}
