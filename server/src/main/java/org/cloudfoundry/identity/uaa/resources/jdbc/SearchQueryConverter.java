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

import org.springframework.util.MultiValueMap;

import java.util.List;
import java.util.Map;

public interface SearchQueryConverter {

    final class ProcessedFilter {
        public static final String ORDER_BY_NO_SPACE = "ORDER BY";
        public static final String ORDER_BY = " " + ORDER_BY_NO_SPACE + " ";
        private final String sql;
        private final Map<String, Object> params;
        private final boolean hasOrderBy;

        public String getParamPrefix() {
            return paramPrefix;
        }

        public void setParamPrefix(String paramPrefix) {
            this.paramPrefix = paramPrefix;
        }

        private String paramPrefix;

        public String getSql() {
            return sql;
        }

        public boolean hasOrderBy() {
            return hasOrderBy;
        }

        public Map<String, Object> getParams() {
            return params;
        }

        public ProcessedFilter(String sql, Map<String, Object> params, boolean hasOrderBy) {
            this.sql = sql;
            this.params = params;
            this.hasOrderBy = hasOrderBy;
        }

        @Override
        public String toString() {
            return "sql: %s, params: %s".formatted(sql, params);
        }
    }

    ProcessedFilter convert(String filter, String sortBy, boolean ascending, String zoneId);

    MultiValueMap<String, Object> getFilterValues(String filter, List<String> validAttributes) throws IllegalArgumentException;

    String map(String attribute);

    String getJoinName();
}
