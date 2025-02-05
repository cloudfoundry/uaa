/*
 * *****************************************************************************
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

import java.util.List;
import java.util.Map;

import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Component;

/**
 * Singleton factory for creating a JdbcPagingList instance with the correct DB
 * specific singleton "Adapter(s)"
 * 
 * @author Mike Youngstrom
 */
@Component
public class JdbcPagingListFactory {

    private final NamedParameterJdbcTemplate jdbcTemplate;
    private final LimitSqlAdapter limitSqlAdapter;

    public JdbcPagingListFactory(NamedParameterJdbcTemplate jdbcTemplate, LimitSqlAdapter limitSqlAdapter) {
        this.jdbcTemplate = jdbcTemplate;
        this.limitSqlAdapter = limitSqlAdapter;
    }

    public <T> List<T> createJdbcPagingList(String sql, Map<String, ?> args, RowMapper<T> mapper, int pageSize) {
        return new JdbcPagingList<>(jdbcTemplate, limitSqlAdapter, sql, args, mapper, pageSize);
    }
}
