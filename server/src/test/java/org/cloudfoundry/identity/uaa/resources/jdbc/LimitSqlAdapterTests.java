package org.cloudfoundry.identity.uaa.resources.jdbc;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;

import static org.assertj.core.api.Assertions.assertThat;

@WithDatabaseContext
class LimitSqlAdapterTests {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private LimitSqlAdapter limitSqlAdapter;

    @BeforeEach
    void setUpLimitSqlAdapterTests() {
        jdbcTemplate.update("create table delete_top_rows_test (id varchar(10), expires integer, payload varchar(20))");
        jdbcTemplate.update("insert into delete_top_rows_test values (?,?,?)", "X", 1, "some-data");
        jdbcTemplate.update("insert into delete_top_rows_test values (?,?,?)", "M", 2, "some-data");
        jdbcTemplate.update("insert into delete_top_rows_test values (?,?,?)", "K", 3, "some-data");
        jdbcTemplate.update("insert into delete_top_rows_test values (?,?,?)", "D", 4, "some-data");
        jdbcTemplate.update("insert into delete_top_rows_test values (?,?,?)", "A", 5, "some-data");
    }

    @AfterEach
    void tearDown() {
        jdbcTemplate.update("drop table delete_top_rows_test");
    }

    @Test
    void revocableTokenDeleteSyntax() {
        //tests that the query succeed, nothing else
        String query = limitSqlAdapter.getDeleteExpiredQuery("revocable_tokens", "token_id", "expires_at", 500);
        jdbcTemplate.update(query, System.currentTimeMillis());
    }

    @Test
    void deleteTopRows() {
        assertThat((int) jdbcTemplate.queryForObject("select count(*) from delete_top_rows_test where id = 'X'", Integer.class)).isOne();
        assertThat((int) jdbcTemplate.queryForObject("select count(*) from delete_top_rows_test where id = 'A'", Integer.class)).isOne();
        jdbcTemplate.update(
                limitSqlAdapter.getDeleteExpiredQuery(
                        "delete_top_rows_test",
                        "id",
                        "expires",
                        2
                ),
                5
        );
        assertThat((int) jdbcTemplate.queryForObject("select count(*) from delete_top_rows_test where id = 'K'", Integer.class)).isOne();
        assertThat((int) jdbcTemplate.queryForObject("select count(*) from delete_top_rows_test where id = 'D'", Integer.class)).isOne();
        assertThat((int) jdbcTemplate.queryForObject("select count(*) from delete_top_rows_test where id = 'A'", Integer.class)).isOne();
        assertThat((int) jdbcTemplate.queryForObject("select count(*) from delete_top_rows_test", Integer.class)).isEqualTo(3);
    }
}