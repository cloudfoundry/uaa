package org.cloudfoundry.identity.uaa.resources.jdbc;

import org.junit.jupiter.api.Test;

import static org.junit.Assert.assertTrue;

class SQLServerLimitSqlAdapterTest {
    @Test
    void testSQLServerLimit() {
        SQLServerLimitSqlAdapter sqlServerLimitAdapter = new SQLServerLimitSqlAdapter();
        String originSql = "select * from table1 order by column_name";
        String generatedSql = sqlServerLimitAdapter.getLimitSql(originSql, 1, 1);
        assertTrue(generatedSql.equalsIgnoreCase("select * from table1 order by column_name OFFSET 1 ROWS FETCH NEXT 1 ROWS ONLY;"));

        originSql = "select * from table1 order by column_name asc";
        generatedSql = sqlServerLimitAdapter.getLimitSql(originSql, 1, 1);
        assertTrue(generatedSql.equalsIgnoreCase("select * from table1 order by column_name asc OFFSET 1 ROWS FETCH NEXT 1 ROWS ONLY;"));

        originSql = "select * from table1 order by column_name desc";
        generatedSql = sqlServerLimitAdapter.getLimitSql(originSql, 1, 1);
        assertTrue(generatedSql.equalsIgnoreCase("select * from table1 order by column_name desc OFFSET 1 ROWS FETCH NEXT 1 ROWS ONLY;"));

        originSql = "select * from table1";
        generatedSql = sqlServerLimitAdapter.getLimitSql(originSql, 1, 1);
        assertTrue(generatedSql.equalsIgnoreCase("select * from table1 ORDER BY 1 OFFSET 1 ROWS FETCH NEXT 1 ROWS ONLY;"));
    }
}