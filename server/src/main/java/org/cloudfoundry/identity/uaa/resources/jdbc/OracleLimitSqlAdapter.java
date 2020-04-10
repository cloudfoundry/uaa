
package org.cloudfoundry.identity.uaa.resources.jdbc;

public class OracleLimitSqlAdapter implements LimitSqlAdapter {

    @Override
    public String getLimitSql(String sql, int index, int size) {
        index++; // Oracle "rownum" is 1 based
        return "select * from (select a.*, ROWNUM rnum from (" + sql + ") a where rownum <= " + index + size
                        + ") where rnum >= " + index;
    }

    @Override
    public String getDeleteExpiredQuery(String tablename, String primaryKeyColumn, String expiresColumn, int maxRows) {
        throw new UnsupportedOperationException();
    }
}
