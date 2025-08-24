/*
 * ****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 * ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.resources.jdbc;

public class HsqlDbLimitSqlAdapter implements LimitSqlAdapter {

    @Override
    public String getDeleteExpiredQuery(String tablename, String primaryKeyColumn, String expiresColumn, int maxRows) {
        return "DELETE FROM " +
                tablename +
                " WHERE " +
                primaryKeyColumn + " IN " +
                "(SELECT " + primaryKeyColumn +
                " FROM " + tablename +
                " WHERE " + expiresColumn + " < ?" +
                " ORDER BY " + expiresColumn +
                " LIMIT " + maxRows + " OFFSET 0)";
    }
}
