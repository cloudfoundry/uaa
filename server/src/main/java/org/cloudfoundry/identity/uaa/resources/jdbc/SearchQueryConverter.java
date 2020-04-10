package org.cloudfoundry.identity.uaa.resources.jdbc;

import java.util.List;
import java.util.Map;
import org.springframework.util.MultiValueMap;

public interface SearchQueryConverter {

  ProcessedFilter convert(String filter, String sortBy, boolean ascending, String zoneId);

  MultiValueMap<String, Object> getFilterValues(String filter, List<String> validAttributes)
      throws IllegalArgumentException;

  String map(String attribute);

  final class ProcessedFilter {

    public static final String ORDER_BY_NO_SPACE = "ORDER BY";
    public static final String ORDER_BY = " " + ORDER_BY_NO_SPACE + " ";
    private final String sql;
    private final Map<String, Object> params;
    private final boolean hasOrderBy;
    private String paramPrefix;

    public ProcessedFilter(String sql, Map<String, Object> params, boolean hasOrderBy) {
      this.sql = sql;
      this.params = params;
      this.hasOrderBy = hasOrderBy;
    }

    public String getParamPrefix() {
      return paramPrefix;
    }

    public void setParamPrefix(String paramPrefix) {
      this.paramPrefix = paramPrefix;
    }

    public String getSql() {
      return sql;
    }

    public boolean hasOrderBy() {
      return hasOrderBy;
    }

    public Map<String, Object> getParams() {
      return params;
    }

    @Override
    public String toString() {
      return String.format("sql: %s, params: %s", sql, params);
    }
  }
}
