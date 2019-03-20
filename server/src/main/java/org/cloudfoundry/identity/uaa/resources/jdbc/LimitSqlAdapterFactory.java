package org.cloudfoundry.identity.uaa.resources.jdbc;

import java.util.Collection;

import static org.apache.commons.lang3.StringUtils.contains;
import static org.apache.commons.lang3.StringUtils.join;

@Deprecated
// This class does not appear to be used anywhere in the production code.
public class LimitSqlAdapterFactory {

    public static LimitSqlAdapter getLimitSqlAdapter() {
        return getLimitSqlAdapter(System.getProperty("spring.profiles.active"));
    }

    static LimitSqlAdapter getLimitSqlAdapter(String profiles) {
        if(contains(profiles, "sqlserver")) {
            return new SQLServerLimitSqlAdapter();
        }

        if(contains(profiles, "postgresql")) {
            return new PostgresLimitSqlAdapter();
        }

        if(contains(profiles, "mysql")) {
            return new MySqlLimitSqlAdapter();
        }

        return new HsqlDbLimitSqlAdapter();
    }

    static LimitSqlAdapter getLimitSqlAdapter(Collection<String> profiles) {
        if (profiles == null) {
            return new HsqlDbLimitSqlAdapter();
        }

        return getLimitSqlAdapter(join(profiles, ","));
    }

}
