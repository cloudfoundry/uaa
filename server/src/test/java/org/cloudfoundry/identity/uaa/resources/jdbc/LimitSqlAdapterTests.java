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

import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class LimitSqlAdapterTests extends JdbcTestBase {

    @Before
    public void setup() throws Exception {
        jdbcTemplate.update("create table delete_top_rows_test (id varchar(10), expires integer, payload varchar(20))");
        jdbcTemplate.update("insert into delete_top_rows_test values (?,?,?)", "X", 1, "some-data");
        jdbcTemplate.update("insert into delete_top_rows_test values (?,?,?)", "M", 2, "some-data");
        jdbcTemplate.update("insert into delete_top_rows_test values (?,?,?)", "K", 3, "some-data");
        jdbcTemplate.update("insert into delete_top_rows_test values (?,?,?)", "D", 4, "some-data");
        jdbcTemplate.update("insert into delete_top_rows_test values (?,?,?)", "A", 5, "some-data");
    }

    @After
    public void dropTable() {
        jdbcTemplate.update("drop table delete_top_rows_test");
    }

    @Test
    public void revocable_token_delete_syntax() throws Exception {
        //tests that the query succeed, nothing else
        String query = limitSqlAdapter.getDeleteExpiredQuery("revocable_tokens", "token_id", "expires_at", 500);
        jdbcTemplate.update(query, System.currentTimeMillis());
    }

    @Test
    public void test_delete_top_rows() throws Exception {
        assertEquals(1, (int) jdbcTemplate.queryForObject("select count(*) from delete_top_rows_test where id = 'X'", Integer.class));
        assertEquals(1, (int) jdbcTemplate.queryForObject("select count(*) from delete_top_rows_test where id = 'A'", Integer.class));
        jdbcTemplate.update(
            limitSqlAdapter.getDeleteExpiredQuery(
                "delete_top_rows_test",
                "id",
                "expires",
                2
            ),
            5
        );
        assertEquals(1, (int) jdbcTemplate.queryForObject("select count(*) from delete_top_rows_test where id = 'K'", Integer.class));
        assertEquals(1, (int) jdbcTemplate.queryForObject("select count(*) from delete_top_rows_test where id = 'D'", Integer.class));
        assertEquals(1, (int) jdbcTemplate.queryForObject("select count(*) from delete_top_rows_test where id = 'A'", Integer.class));
        assertEquals(3, (int) jdbcTemplate.queryForObject("select count(*) from delete_top_rows_test", Integer.class));
    }


}