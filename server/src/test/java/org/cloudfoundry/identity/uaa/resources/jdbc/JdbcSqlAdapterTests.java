package org.cloudfoundry.identity.uaa.resources.jdbc;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Test;

public class JdbcSqlAdapterTests {
    @Test
    public void testSQLServerLimit() throws Exception {
        SQLServerLimitSqlAdapter sqlServerLimitAdapter = new SQLServerLimitSqlAdapter();
        String originSql = "select * from table1 order by colume1";
        String generatedSql = sqlServerLimitAdapter.getLimitSql(originSql, 1, 1);
        assertTrue(generatedSql.equalsIgnoreCase("select * from table1 order by colume1 OFFSET 1 ROWS FETCH NEXT 1 ROWS ONLY;"));
        
        originSql = "select * from table1 order by colume1 asc";
        generatedSql = sqlServerLimitAdapter.getLimitSql(originSql, 1, 1);
        assertTrue(generatedSql.equalsIgnoreCase("select * from table1 order by colume1 asc OFFSET 1 ROWS FETCH NEXT 1 ROWS ONLY;"));
        
        originSql = "select * from table1 order by colume1 desc";
        generatedSql = sqlServerLimitAdapter.getLimitSql(originSql, 1, 1);
        assertTrue(generatedSql.equalsIgnoreCase("select * from table1 order by colume1 desc OFFSET 1 ROWS FETCH NEXT 1 ROWS ONLY;"));     
        
        originSql = "select * from table1";
        generatedSql = sqlServerLimitAdapter.getLimitSql(originSql, 1, 1);
        assertTrue(generatedSql.equalsIgnoreCase("select * from table1 ORDER BY 1 OFFSET 1 ROWS FETCH NEXT 1 ROWS ONLY;")); 
    }

    @Test
    public void testSQLBooleanValue() throws Exception{
        SQLServerBooleanValueAdapter sqlServerBooleanAdapter = new SQLServerBooleanValueAdapter();
        assertEquals(sqlServerBooleanAdapter.getTrueValue(), 1);
        assertEquals(sqlServerBooleanAdapter.getFalseValue(), 0);

        DefaultBooleanValueAdapter defaultBooleanAdapter = new DefaultBooleanValueAdapter();
        assertEquals(defaultBooleanAdapter.getTrueValue(), true);
        assertEquals(defaultBooleanAdapter.getFalseValue(), false);
    }
}