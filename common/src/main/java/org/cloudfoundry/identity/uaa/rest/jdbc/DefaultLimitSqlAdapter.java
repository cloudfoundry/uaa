package org.cloudfoundry.identity.uaa.rest.jdbc;

public class DefaultLimitSqlAdapter implements LimitSqlAdapter {

	@Override
	public String getLimitSql(String sql, int index, int size) {
		return sql + " limit " + size + " offset " + index;
	}

}
