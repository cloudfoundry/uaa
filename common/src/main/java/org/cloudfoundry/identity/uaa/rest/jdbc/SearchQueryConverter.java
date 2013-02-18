package org.cloudfoundry.identity.uaa.rest.jdbc;

import org.cloudfoundry.identity.uaa.rest.AttributeNameMapper;

import java.util.Map;

public interface SearchQueryConverter {

	public static final class ProcessedFilter {
		private final String sql;
		private final Map<String, Object> params;

		public String getSql() {
			return sql;
		}

		public Map<String, Object> getParams() {
			return params;
		}

		public ProcessedFilter(String sql, Map<String, Object> params) {
			this.sql = sql;
			this.params = params;
		}

		@Override
		public String toString() {
			return String.format("sql: %s, params: %s", sql, params);
		}
	}

	ProcessedFilter convert(String filter, String sortBy, boolean ascending);

	ProcessedFilter convert(String filter, String sortBy, boolean ascending, AttributeNameMapper mapper);

}
