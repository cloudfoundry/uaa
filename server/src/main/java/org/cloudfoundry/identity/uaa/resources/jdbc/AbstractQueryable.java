/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.resources.jdbc;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.resources.Queryable;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.util.StringUtils;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

public abstract class AbstractQueryable<T> implements Queryable<T> {

    private NamedParameterJdbcTemplate jdbcTemplate;

    private JdbcPagingListFactory pagingListFactory;

    protected RowMapper<T> rowMapper;

    private final Log logger = LogFactory.getLog(getClass());

    private SearchQueryConverter queryConverter = null;

    private int pageSize = 200;

    protected AbstractQueryable(JdbcTemplate jdbcTemplate, JdbcPagingListFactory pagingListFactory,
                    RowMapper<T> rowMapper) {
        queryConverter = new SimpleSearchQueryConverter();
        this.jdbcTemplate = new NamedParameterJdbcTemplate(jdbcTemplate);
        this.pagingListFactory = pagingListFactory;
        this.rowMapper = rowMapper;
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
        if (StringUtils.hasText(filter)) {
            filter = "("+ filter+ ") and";
        }
        filter += " identity_zone_id eq \""+ zoneId +"\"";

        SearchQueryConverter.ProcessedFilter where = queryConverter.convert(filter, sortBy, ascending);
        logger.debug("Filtering groups with SQL: " + where);
        List<T> result;
        try {
            String completeSql = getQuerySQL(filter, where);
            logger.debug("complete sql: " + completeSql + ", params: " + where.getParams());
            if (pageSize > 0 && pageSize < Integer.MAX_VALUE) {
                result = pagingListFactory.createJdbcPagingList(completeSql, where.getParams(), rowMapper, pageSize);
            }
            else {
                result = jdbcTemplate.query(completeSql, where.getParams(), rowMapper);
            }
            return result;
        } catch (DataAccessException e) {
            logger.debug("Filter '" + filter + "' generated invalid SQL", e);
            throw new IllegalArgumentException("Invalid filter: " + filter);
        }
    }

    protected String getQuerySQL(String filter, SearchQueryConverter.ProcessedFilter where) {
        if (filter == null || filter.trim().length()==0) {
            return getBaseSqlQuery();
        }
        if (where.hasOrderBy()) {
            return getBaseSqlQuery() + " where (" + where.getSql().replace(where.ORDER_BY, ")"+where.ORDER_BY);
        } else {
            return getBaseSqlQuery() + " where (" + where.getSql() + ")";
        }
    }

    protected abstract String getBaseSqlQuery();
    protected abstract String getTableName();

    protected abstract void validateOrderBy(String orderBy) throws IllegalArgumentException;

    protected void validateOrderBy(String orderBy, String fields) throws IllegalArgumentException {
        if (!StringUtils.hasText(orderBy)) {
            return;
        }
        String[] input = StringUtils.commaDelimitedListToStringArray(orderBy);
        Set<String> compare = new HashSet<>();
        StringUtils.commaDelimitedListToSet(fields)
                .stream()
                .forEach(p -> compare.add(p.toLowerCase().trim()));
        boolean allints = true;
        for (String s : input) {
            try {
                Integer.parseInt(s);
            } catch (NumberFormatException e) {
                allints = false;
                if (!compare.contains(s.toLowerCase().trim())) {
                    throw new IllegalArgumentException("Invalid sort field:"+s);
                }
            }
        }
        if (allints) {
            return;
        }
    }

}
