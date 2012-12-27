package org.cloudfoundry.identity.uaa.scim;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcPagingList;
import org.cloudfoundry.identity.uaa.scim.jdbc.ScimSearchQueryConverter;
import org.cloudfoundry.identity.uaa.scim.jdbc.SearchQueryConverter;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.util.StringUtils;

import java.util.List;

public abstract class AbstractQueriable<T> implements Queriable<T> {

	private NamedParameterJdbcTemplate jdbcTemplate;

	private RowMapper<T> rowMapper;

	private final Log logger = LogFactory.getLog(getClass());

	private SearchQueryConverter queryConverter = new ScimSearchQueryConverter();

	private boolean pagination = true;

	private static final String QUERY_TEMPLATE = "select * from %s where %s";

	public void setQueryConverter(SearchQueryConverter queryConverter) {
		this.queryConverter = queryConverter;
	}

	public void setPagination(boolean pagination) {
		this.pagination = pagination;
	}

	@Override
	public List<T> query(String filter) {
		return query(filter, null, true);
	}

	@Override
	public List<T> query(String filter, String sortBy, boolean ascending) {
//		SearchQueryConverter.ProcessedFilter where = queryConverter.convert(filter, StringUtils.hasText(sortBy) ? sortBy : "created", ascending);
		SearchQueryConverter.ProcessedFilter where = queryConverter.convert(filter, sortBy, ascending);
		logger.debug("Filtering groups with SQL: " + where);
		List<T> result;
		try {
			String completeSql = getBaseSqlQuery() + " where " + where.getSql();
			logger.debug("complete sql: " + completeSql + ", params: " + where.getParams());
			if (pagination) {
				result = new JdbcPagingList<T>(jdbcTemplate, completeSql, where.getParams(), rowMapper, 200);
			} else {
				result = jdbcTemplate.query(completeSql, where.getParams(), rowMapper);
			}
			return result;
		}
		catch (DataAccessException e) {
			logger.debug("Filter '" + filter + "' generated invalid SQL", e);
			throw new IllegalArgumentException("Invalid filter: " + filter);
		}
	}
	
//	public List<T> query2(String filter, String sortBy, boolean ascending) {
//
//		SearchQueryConverter.ProcessedFilter where = queryConverter.convert(filter, sortBy,  ascending);
//		logger.debug("Filtering users with SQL: " + where);
//
//		try {
//			String completeSql = ALL_USERS + " where " + where.getSql();
//			logger.debug("complete sql: " + completeSql + ", params: " + where.getParams());
//			return new JdbcPagingList<ScimUser>(jdbcTemplate, ALL_USERS + " where " + where.getSql(), where.getParams(), mapper,
//													   200);
//		}
//		catch (DataAccessException e) {
//			logger.debug("Filter '" + filter + "' generated invalid SQL", e);
//			throw new IllegalArgumentException("Invalid filter: " + filter);
//		}
//	}

	protected abstract String getBaseSqlQuery();

	protected AbstractQueriable(JdbcTemplate jdbcTemplate, RowMapper<T> rowMapper) {
		this.jdbcTemplate = new NamedParameterJdbcTemplate(jdbcTemplate);
		this.rowMapper = rowMapper;
	}
}
