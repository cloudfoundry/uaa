package org.cloudfoundry.identity.uaa.resources.jdbc;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.ColumnMapRowMapper;
import org.springframework.jdbc.core.JdbcTemplate;

import javax.sql.DataSource;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

@WithDatabaseContext
class JdbcPagingListTests {

    private List<Map<String, Object>> list;

    private JdbcTemplate jdbcTemplate;

    @Autowired
    private LimitSqlAdapter limitSqlAdapter;

    @BeforeEach
    public void initJdbcPagingListTests(@Autowired DataSource dataSource) {

        jdbcTemplate = new JdbcTemplate(dataSource);
        jdbcTemplate.execute("create table foo (id integer primary key, name varchar(10) not null)");
        jdbcTemplate.execute("insert into foo (id, name) values (0, 'foo')");
        jdbcTemplate.execute("insert into foo (id, name) values (1, 'bar')");
        jdbcTemplate.execute("insert into foo (id, name) values (2, 'baz')");
        jdbcTemplate.execute("insert into foo (id, name) values (3, 'zab')");
        jdbcTemplate.execute("insert into foo (id, name) values (4, 'rab')");

    }

    @AfterEach
    public void dropFoo() {
        jdbcTemplate.execute("drop table foo");
    }

    @Test
    void iterationOverPages() {
        list = new JdbcPagingList<Map<String, Object>>(jdbcTemplate, limitSqlAdapter, "SELECT * from foo where id>=:id",
                Collections.<String, Object>singletonMap("id", 0), new ColumnMapRowMapper(), 3);
        assertEquals(5, list.size());
        Set<String> names = new HashSet<String>();
        for (Map<String, Object> map : list) {
            String name = (String) map.get("name");
            assertNotNull(name);
            names.add(name);
        }
        assertEquals(5, names.size());
        names = new HashSet<String>();
        for (Map<String, Object> map : list) {
            String name = (String) map.get("name");
            assertNotNull(name);
            names.add(name);
        }
        assertEquals(5, names.size());
    }

    @Test
    void iterationWithDeletedElements() {
        list = new JdbcPagingList<Map<String, Object>>(jdbcTemplate, limitSqlAdapter, "SELECT * from foo where id>=:id",
                Collections.<String, Object>singletonMap("id", 0), new ColumnMapRowMapper(), 3);
        jdbcTemplate.update("DELETE from foo where id>3");
        assertEquals(5, list.size());
        Set<String> names = new HashSet<String>();
        for (Map<String, Object> map : list) {
            String name = (String) map.get("name");
            assertNotNull(name);
            names.add(name);
        }
        assertEquals(4, names.size());
    }

    @Test
    void orderBy() {
        list = new JdbcPagingList<Map<String, Object>>(jdbcTemplate, limitSqlAdapter, "SELECT * from foo order by id asc",
                Collections.<String, Object>singletonMap("id", 0), new ColumnMapRowMapper(), 3);
        assertEquals(5, list.size());
        Set<String> names = new HashSet<String>();
        for (Map<String, Object> map : list) {
            String name = (String) map.get("name");
            assertNotNull(name);
            names.add(name);
        }
        assertEquals(5, names.size());
    }

    @Test
    void jumpOverPages() {
        list = new JdbcPagingList<Map<String, Object>>(jdbcTemplate, limitSqlAdapter, "SELECT * from foo",
                new ColumnMapRowMapper(), 3);
        Map<String, Object> map = list.get(3);
        assertNotNull(map.get("name"));
    }

    @Test
    void iterationOverSubList() {
        list = new JdbcPagingList<Map<String, Object>>(jdbcTemplate, limitSqlAdapter, "SELECT * from foo",
                new ColumnMapRowMapper(), 3);
        list = list.subList(1, 4);
        assertEquals(3, list.size());
        int count = 0;
        for (Map<String, Object> map : list) {
            count++;
            assertNotNull(map.get("name"));
        }
        assertEquals(3, count);
    }

    @Test
    void iterationOverSubListWithSameSize() {
        list = new JdbcPagingList<Map<String, Object>>(jdbcTemplate, limitSqlAdapter, "SELECT * from foo",
                new ColumnMapRowMapper(), 3);
        list = list.subList(0, 5);
        assertEquals(5, list.size());
        int count = 0;
        for (Map<String, Object> map : list) {
            count++;
            assertNotNull(map.get("name"));
        }
        assertEquals(5, count);
    }

    @Test
    void subListExtendsBeyondSize() {
        list = new JdbcPagingList<Map<String, Object>>(jdbcTemplate, limitSqlAdapter, "SELECT * from foo",
                new ColumnMapRowMapper(), 3);
        assertThrows(IndexOutOfBoundsException.class, () -> list.subList(1, 40));
    }

    @Test
    void subListFromDeletedElements() {
        list = new JdbcPagingList<Map<String, Object>>(jdbcTemplate, limitSqlAdapter, "SELECT * from foo",
                new ColumnMapRowMapper(), 3);
        jdbcTemplate.update("DELETE from foo where id>3");
        list = list.subList(1, list.size());
        assertEquals(4, list.size());
        int count = 0;
        for (Map<String, Object> map : list) {
            count++;
            assertNotNull(map.get("name"));
        }
        assertEquals(3, count); // count is less than original size estimate
    }

}
