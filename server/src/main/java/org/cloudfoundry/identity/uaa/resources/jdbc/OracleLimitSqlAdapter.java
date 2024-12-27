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

public class OracleLimitSqlAdapter implements LimitSqlAdapter {

    @Override
    public String getLimitSql(String sql, int index, int size) {
        index++; // Oracle "rownum" is 1 based
        return "select * from (select a.*, ROWNUM rnum from (" + sql + ") a where rownum <= " + index + size
                + ") where rnum >= " + index;
    }

    @Override
    public String getDeleteExpiredQuery(String tablename, String primaryKeyColumn, String expiresColumn, int maxRows) {
        throw new UnsupportedOperationException();
    }
}
