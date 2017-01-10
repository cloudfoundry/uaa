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

import java.util.Collection;

import static org.springframework.util.StringUtils.hasText;

public class LimitSqlAdapterFactory {

    public static LimitSqlAdapter getLimitSqlAdapter() {
        return getLimitSqlAdapter(System.getProperty("spring.profiles.active",""));
    }

    public static LimitSqlAdapter getLimitSqlAdapter(String profiles) {
        if (hasText(profiles) && profiles.contains("sqlserver")) {
            return new SQLServerLimitSqlAdapter();
        }
        return new DefaultLimitSqlAdapter();
    }

    public static LimitSqlAdapter getLimitSqlAdapter(Collection<String> profiles) {
        if (profiles!=null && profiles.contains("sqlserver")) {
            return new SQLServerLimitSqlAdapter();
        }
        return new DefaultLimitSqlAdapter();
    }

}
