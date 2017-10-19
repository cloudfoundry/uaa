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

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import java.util.Arrays;
import java.util.Collection;

import static java.util.Collections.EMPTY_LIST;
import static org.junit.Assert.assertSame;


public class LimitSqlAdapterFactoryTest {

    private static String defaultProfiles = null;

    @BeforeClass
    public static void saveProfiles() {
        defaultProfiles = System.getProperty("spring.profiles.active");
        System.clearProperty("spring.profiles.active");
    }

    @AfterClass
    public static void restoreProfiles() {
        if (defaultProfiles!=null) {
            System.setProperty("spring.profiles.active", defaultProfiles);
        }
    }

    @Test
    public void getLimitSqlAdapter_no_args() throws Exception {
        assertSame(HsqlDbLimitSqlAdapter.class, LimitSqlAdapterFactory.getLimitSqlAdapter().getClass());
        System.setProperty("spring.profiles.active", "mysql");
        assertSame(MySqlLimitSqlAdapter.class, LimitSqlAdapterFactory.getLimitSqlAdapter().getClass());
        System.setProperty("spring.profiles.active", "postgresql");
        assertSame(PostgresLimitSqlAdapter.class, LimitSqlAdapterFactory.getLimitSqlAdapter().getClass());
        System.setProperty("spring.profiles.active", "mysql,default");
        assertSame(MySqlLimitSqlAdapter.class, LimitSqlAdapterFactory.getLimitSqlAdapter().getClass());
        System.setProperty("spring.profiles.active", "");
        assertSame(HsqlDbLimitSqlAdapter.class, LimitSqlAdapterFactory.getLimitSqlAdapter().getClass());
        System.setProperty("spring.profiles.active", "sqlserver");
        assertSame(SQLServerLimitSqlAdapter.class, LimitSqlAdapterFactory.getLimitSqlAdapter().getClass());
        System.setProperty("spring.profiles.active", "default,sqlserver");
        assertSame(SQLServerLimitSqlAdapter.class, LimitSqlAdapterFactory.getLimitSqlAdapter().getClass());
        System.setProperty("spring.profiles.active", "sqlserver,default");
        assertSame(SQLServerLimitSqlAdapter.class, LimitSqlAdapterFactory.getLimitSqlAdapter().getClass());
        System.clearProperty("spring.profiles.active");
        assertSame(HsqlDbLimitSqlAdapter.class, LimitSqlAdapterFactory.getLimitSqlAdapter().getClass());
    }

    @Test
    public void getLimitSqlAdapter_profiles_arg() throws Exception {
        assertSame(HsqlDbLimitSqlAdapter.class, LimitSqlAdapterFactory.getLimitSqlAdapter((String) null).getClass());
        assertSame(MySqlLimitSqlAdapter.class, LimitSqlAdapterFactory.getLimitSqlAdapter("mysql").getClass());
        assertSame(MySqlLimitSqlAdapter.class, LimitSqlAdapterFactory.getLimitSqlAdapter("mysql,default").getClass());
        assertSame(HsqlDbLimitSqlAdapter.class, LimitSqlAdapterFactory.getLimitSqlAdapter("").getClass());
        assertSame(SQLServerLimitSqlAdapter.class, LimitSqlAdapterFactory.getLimitSqlAdapter("sqlserver").getClass());
        assertSame(SQLServerLimitSqlAdapter.class, LimitSqlAdapterFactory.getLimitSqlAdapter("default,sqlserver").getClass());
        assertSame(SQLServerLimitSqlAdapter.class, LimitSqlAdapterFactory.getLimitSqlAdapter("sqlserver,default").getClass());
        assertSame(PostgresLimitSqlAdapter.class, LimitSqlAdapterFactory.getLimitSqlAdapter("postgresql").getClass());
        assertSame(PostgresLimitSqlAdapter.class, LimitSqlAdapterFactory.getLimitSqlAdapter("default,postgresql").getClass());
        assertSame(PostgresLimitSqlAdapter.class, LimitSqlAdapterFactory.getLimitSqlAdapter("postgresql,default").getClass());
    }

    @Test
    public void getLimitSqlAdapter_list_args() throws Exception {
        assertSame(HsqlDbLimitSqlAdapter.class, LimitSqlAdapterFactory.getLimitSqlAdapter((Collection<String>) null).getClass());
        assertSame(MySqlLimitSqlAdapter.class, LimitSqlAdapterFactory.getLimitSqlAdapter(Arrays.asList("mysql")).getClass());
        assertSame(MySqlLimitSqlAdapter.class, LimitSqlAdapterFactory.getLimitSqlAdapter(Arrays.asList("mysql","default")).getClass());
        assertSame(HsqlDbLimitSqlAdapter.class, LimitSqlAdapterFactory.getLimitSqlAdapter(EMPTY_LIST).getClass());
        assertSame(SQLServerLimitSqlAdapter.class, LimitSqlAdapterFactory.getLimitSqlAdapter(Arrays.asList("sqlserver")).getClass());
        assertSame(SQLServerLimitSqlAdapter.class, LimitSqlAdapterFactory.getLimitSqlAdapter(Arrays.asList("default","sqlserver")).getClass());
        assertSame(SQLServerLimitSqlAdapter.class, LimitSqlAdapterFactory.getLimitSqlAdapter(Arrays.asList("sqlserver","default")).getClass());
        assertSame(PostgresLimitSqlAdapter.class, LimitSqlAdapterFactory.getLimitSqlAdapter(Arrays.asList("postgresql")).getClass());
        assertSame(PostgresLimitSqlAdapter.class, LimitSqlAdapterFactory.getLimitSqlAdapter(Arrays.asList("default","postgresql")).getClass());
        assertSame(PostgresLimitSqlAdapter.class, LimitSqlAdapterFactory.getLimitSqlAdapter(Arrays.asList("postgresql","default")).getClass());
    }

}