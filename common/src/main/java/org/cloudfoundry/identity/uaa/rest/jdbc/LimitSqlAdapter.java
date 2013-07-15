package org.cloudfoundry.identity.uaa.rest.jdbc;

public interface LimitSqlAdapter {

	public String getLimitSql(String sql, int index, int size); 
}
