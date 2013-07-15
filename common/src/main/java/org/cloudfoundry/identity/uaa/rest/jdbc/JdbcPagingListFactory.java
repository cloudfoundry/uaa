package org.cloudfoundry.identity.uaa.rest.jdbc;

import java.util.List;
import java.util.Map;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

/**
 * Singleton factory for creating a JdbcPagingList instance with the correct DB specific singleton "Adapter(s)"
 * 
 * @author Mike Youngstrom
 */
public class JdbcPagingListFactory {

	private NamedParameterJdbcTemplate jdbcTemplate;
	private LimitSqlAdapter limitSqlAdapter;
	
	public JdbcPagingListFactory(JdbcTemplate jdbcTemplate, LimitSqlAdapter limitSqlAdapter) {
		this.jdbcTemplate = new NamedParameterJdbcTemplate(jdbcTemplate);
		this.limitSqlAdapter = limitSqlAdapter;
	}

	public <T> List<T> createJdbcPagingList(String sql, Map<String, ?> args, RowMapper<T> mapper, int pageSize) {
		return new JdbcPagingList<T>(jdbcTemplate, limitSqlAdapter, sql, args, mapper, pageSize);
	}
}
