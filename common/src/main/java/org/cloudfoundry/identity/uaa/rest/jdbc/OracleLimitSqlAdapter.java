package org.cloudfoundry.identity.uaa.rest.jdbc;

public class OracleLimitSqlAdapter implements LimitSqlAdapter {

	@Override
	public String getLimitSql(String sql, int index, int size) {
		index++; //Oracle "rownum" is 1 based
		return "select * from (select a.*, ROWNUM rnum from ("+sql+") a where rownum <= "+index+size+") where rnum >= "+index;
	}

}
