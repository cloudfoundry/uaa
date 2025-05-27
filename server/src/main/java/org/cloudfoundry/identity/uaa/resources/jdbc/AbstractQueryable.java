package org.cloudfoundry.identity.uaa.resources.jdbc;

import org.cloudfoundry.identity.uaa.resources.Queryable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static com.google.common.primitives.Ints.tryParse;
import static org.cloudfoundry.identity.uaa.resources.jdbc.SearchQueryConverter.ProcessedFilter.ORDER_BY;

public abstract class AbstractQueryable<T> implements Queryable<T> {

    protected final NamedParameterJdbcTemplate namedParameterJdbcTemplate;

    protected final JdbcPagingListFactory pagingListFactory;

    protected RowMapper<T> rowMapper;

    private final Logger logger = LoggerFactory.getLogger(getClass());

    private SearchQueryConverter queryConverter;

    private int pageSize = 200;

    protected AbstractQueryable(final NamedParameterJdbcTemplate namedParameterJdbcTemplate,
            final JdbcPagingListFactory pagingListFactory,
            final RowMapper<T> rowMapper) {
        this.namedParameterJdbcTemplate = namedParameterJdbcTemplate;
        this.pagingListFactory = pagingListFactory;
        this.rowMapper = rowMapper;

        queryConverter = new SimpleSearchQueryConverter();
    }

    public void setQueryConverter(SearchQueryConverter queryConverter) {
        this.queryConverter = queryConverter;
    }

    /**
     * The maximum number of items fetched from the database in one hit. If less
     * than or equal to zero, then there is no
     * limit.
     *
     * @param pageSize the page size to use for backing queries (default 200)
     */
    public void setPageSize(int pageSize) {
        this.pageSize = pageSize;
    }

    public int getPageSize() {
        return pageSize;
    }

    @Override
    public List<T> query(String filter, String zoneId) {
        return query(filter, null, true, zoneId);
    }

    @Override
    public List<T> query(String filter, String sortBy, boolean ascending, String zoneId) {
        validateOrderBy(queryConverter.map(sortBy));

        SearchQueryConverter.ProcessedFilter where = queryConverter.convert(filter, sortBy, ascending, zoneId);
        logger.debug("Filtering groups with SQL: {}", where);
        List<T> result;
        try {
            String completeSql = getQuerySQL(where);
            logger.debug("complete sql: {}, params: {}", completeSql, where.getParams());
            if (pageSize > 0 && pageSize < Integer.MAX_VALUE) {
                result = pagingListFactory.createJdbcPagingList(completeSql, where.getParams(), rowMapper, pageSize);
            } else {
                result = namedParameterJdbcTemplate.query(completeSql, where.getParams(), rowMapper);
            }
            return result;
        } catch (DataAccessException e) {
            logger.debug("Filter '{}' generated invalid SQL", filter, e);
            throw new IllegalArgumentException("Invalid filter: " + filter);
        }
    }

    private String getQuerySQL(SearchQueryConverter.ProcessedFilter where) {
        if (where.hasOrderBy()) {
            return getBaseSqlQuery() + " where (" + where.getSql().replace(ORDER_BY, ")" + ORDER_BY);
        } else {
            return getBaseSqlQuery() + " where (" + where.getSql() + ")";
        }
    }

    protected abstract String getBaseSqlQuery();

    protected abstract String getTableName();

    protected abstract void validateOrderBy(String orderBy) throws IllegalArgumentException;

    protected void validateOrderBy(final String csvRequestedOrderBy, final String csvAllowedFields) throws IllegalArgumentException {
        if (!StringUtils.hasText(csvRequestedOrderBy)) {
            return;
        }

        Set<String> lowerCaseRequestedOrderBy = StringUtils.commaDelimitedListToSet(csvRequestedOrderBy)
                .stream()
                .map(String::toLowerCase)
                .map(String::trim)
                .collect(Collectors.toSet());

        Set<String> lowerCaseAllowedFields = StringUtils.commaDelimitedListToSet(csvAllowedFields)
                .stream()
                .map(String::toLowerCase)
                .map(String::trim)
                .collect(Collectors.toSet());

        lowerCaseRequestedOrderBy
                .stream()
                .filter(s -> null == tryParse(s)) // non-integers
                .filter(s -> !lowerCaseAllowedFields.contains(s))
                .findFirst()
                .ifPresent(s -> {
                    throw new IllegalArgumentException("Invalid sort field: " + s);
                });
    }
}
