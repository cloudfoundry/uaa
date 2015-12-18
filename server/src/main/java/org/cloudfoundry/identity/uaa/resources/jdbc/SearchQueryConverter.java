/*******************************************************************************
 *     Cloud Foundry 
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
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

import java.util.Map;

import org.cloudfoundry.identity.uaa.resources.AttributeNameMapper;

public interface SearchQueryConverter {

    public static final class ProcessedFilter {
        private final String sql;
        private final Map<String, Object> params;

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
