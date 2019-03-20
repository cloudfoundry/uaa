package org.cloudfoundry.identity.uaa.resources.jdbc;

import org.cloudfoundry.identity.uaa.impl.config.SpringProfileCleanupExtension;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;

import static java.util.Collections.EMPTY_LIST;
import static org.junit.Assert.assertSame;

@ExtendWith(SpringProfileCleanupExtension.class)
class LimitSqlAdapterFactoryTest {

    @Test
    void getLimitSqlAdapter_no_args() {
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
    void getLimitSqlAdapter_profiles_arg() {
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
    void getLimitSqlAdapter_list_args() {
        assertSame(HsqlDbLimitSqlAdapter.class, LimitSqlAdapterFactory.getLimitSqlAdapter((Collection<String>) null).getClass());
        assertSame(MySqlLimitSqlAdapter.class, LimitSqlAdapterFactory.getLimitSqlAdapter(Collections.singletonList("mysql")).getClass());
        assertSame(MySqlLimitSqlAdapter.class, LimitSqlAdapterFactory.getLimitSqlAdapter(Arrays.asList("mysql","default")).getClass());
        assertSame(HsqlDbLimitSqlAdapter.class, LimitSqlAdapterFactory.getLimitSqlAdapter(EMPTY_LIST).getClass());
        assertSame(SQLServerLimitSqlAdapter.class, LimitSqlAdapterFactory.getLimitSqlAdapter(Collections.singletonList("sqlserver")).getClass());
        assertSame(SQLServerLimitSqlAdapter.class, LimitSqlAdapterFactory.getLimitSqlAdapter(Arrays.asList("default","sqlserver")).getClass());
        assertSame(SQLServerLimitSqlAdapter.class, LimitSqlAdapterFactory.getLimitSqlAdapter(Arrays.asList("sqlserver","default")).getClass());
        assertSame(PostgresLimitSqlAdapter.class, LimitSqlAdapterFactory.getLimitSqlAdapter(Collections.singletonList("postgresql")).getClass());
        assertSame(PostgresLimitSqlAdapter.class, LimitSqlAdapterFactory.getLimitSqlAdapter(Arrays.asList("default","postgresql")).getClass());
        assertSame(PostgresLimitSqlAdapter.class, LimitSqlAdapterFactory.getLimitSqlAdapter(Arrays.asList("postgresql","default")).getClass());
    }

}