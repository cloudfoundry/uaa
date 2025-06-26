package org.cloudfoundry.identity.uaa.resources.jdbc;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.extensions.profiles.DisabledIfProfile;
import org.cloudfoundry.identity.uaa.extensions.profiles.EnabledIfProfile;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.TransientDataAccessResourceException;
import org.springframework.jdbc.BadSqlGrammarException;
import org.springframework.jdbc.core.ColumnMapRowMapper;
import org.springframework.jdbc.core.JdbcTemplate;

import javax.sql.DataSource;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;

@WithDatabaseContext
class JdbcPagingListTests {

    private List<Map<String, Object>> list;

    private JdbcTemplate jdbcTemplate;

    @Autowired
    private LimitSqlAdapter limitSqlAdapter;

    @BeforeEach
    void initJdbcPagingListTests(@Autowired DataSource dataSource) {

        jdbcTemplate = new JdbcTemplate(dataSource);
        jdbcTemplate.execute("drop table if exists foo");
        jdbcTemplate.execute("create table foo (id integer primary key, name varchar(10) not null)");
        jdbcTemplate.execute("insert into foo (id, name) values (0, 'foo')");
        jdbcTemplate.execute("insert into foo (id, name) values (1, 'bar')");
        jdbcTemplate.execute("insert into foo (id, name) values (2, 'baz')");
        jdbcTemplate.execute("insert into foo (id, name) values (3, 'zab')");
        jdbcTemplate.execute("insert into foo (id, name) values (4, 'rab')");
        jdbcTemplate.execute("insert into foo (id, name) values (5, 'FoO')");
    }

    @AfterEach
    void dropFoo() {
        jdbcTemplate.execute("drop table foo");
    }

    @Test
    void iterationOverPages() {
        list = new JdbcPagingList<>(jdbcTemplate, limitSqlAdapter, "SELECT * from foo where id>=:id",
                Collections.<String, Object>singletonMap("id", 0), new ColumnMapRowMapper(), 3);
        assertThat(list).hasSize(6);
        Set<String> names = new HashSet<>();
        for (Map<String, Object> map : list) {
            String name = (String) map.get("name");
            assertThat(name).isNotNull();
            names.add(name);
        }
        assertThat(names).hasSize(6);
        names = new HashSet<>();
        for (Map<String, Object> map : list) {
            String name = (String) map.get("name");
            assertThat(name).isNotNull();
            names.add(name);
        }
        assertThat(names).hasSize(6);
    }

    @Test
    void iterationWithDeletedElements() {
        list = new JdbcPagingList<>(jdbcTemplate, limitSqlAdapter, "SELECT * from foo where id>=:id",
                Collections.<String, Object>singletonMap("id", 0), new ColumnMapRowMapper(), 3);
        jdbcTemplate.update("DELETE from foo where id>3");
        assertThat(list).hasSize(6);
        Set<String> names = new HashSet<>();
        for (Map<String, Object> map : list) {
            String name = (String) map.get("name");
            assertThat(name).isNotNull();
            names.add(name);
        }
        assertThat(names).hasSize(4);
    }

    @Test
    void orderBy() {
        list = new JdbcPagingList<>(jdbcTemplate, limitSqlAdapter, "SELECT * from foo order by id asc",
                Collections.<String, Object>singletonMap("id", 0), new ColumnMapRowMapper(), 3);
        assertThat(list).hasSize(6);
        Set<String> names = new HashSet<>();
        for (Map<String, Object> map : list) {
            String name = (String) map.get("name");
            assertThat(name).isNotNull();
            names.add(name);
        }
        assertThat(names).hasSize(6);
    }

    @Test
    void jumpOverPages() {
        list = new JdbcPagingList<>(jdbcTemplate, limitSqlAdapter, "SELECT * from foo",
                new ColumnMapRowMapper(), 3);
        Map<String, Object> map = list.get(3);
        assertThat(map).containsKey("name");
    }

    @Test
    void selectColumnsFull() {
        list = new JdbcPagingList<>(jdbcTemplate, limitSqlAdapter, "SELECT foo.id, foo.name from foo", new ColumnMapRowMapper(), 3);
        Map<String, Object> map = list.get(3);
        assertThat(map).containsKey("name")
                .containsEntry("name", "zab");
    }

    /**
     * HSQL-db has a different ordering from postgres and mysql
     */
    @Test
    @DisabledIfProfile({"postgresql", "mysql"})
    void selectMoreColumnsWithOrderBy_Hsql() {
        list = new JdbcPagingList<>(jdbcTemplate, limitSqlAdapter, "SELECT foo.id, foo.NAME FrOm foo wHere foo.name = 'FoO' OR foo.name = 'foo' OrDeR By foo.name", new ColumnMapRowMapper(), 3);
        Map<String, Object> map = list.getFirst();
        assertThat(map).containsKey("name")
                .containsEntry("name", "FoO");
        map = list.get(1);
        assertThat(map).containsKey("name")
                .containsEntry("name", "foo");
    }

    @Test
    @EnabledIfProfile({"postgresql", "mysql"})
    void selectMoreColumnsWithOrderBy_PostgresMysql() {
        list = new JdbcPagingList<>(jdbcTemplate, limitSqlAdapter, "SELECT foo.id, foo.NAME FrOm foo wHere foo.name = 'FoO' OR foo.name = 'foo' OrDeR By foo.name", new ColumnMapRowMapper(), 3);
        Map<String, Object> map = list.getFirst();
        assertThat(map).containsEntry("name", "foo");
        map = list.get(1);
        assertThat(map).containsEntry("name", "FoO");
    }

    @Test
    void testWrongStatement() {
        assertThatThrownBy(() -> new JdbcPagingList<>(jdbcTemplate, limitSqlAdapter, "Insert ('6', 'sab') from foo", new ColumnMapRowMapper(), 3))
                .isInstanceOf(BadSqlGrammarException.class);

        assertThatThrownBy(() -> new JdbcPagingList<>(jdbcTemplate, limitSqlAdapter, "SELECT * ", new ColumnMapRowMapper(), 3))
                .isInstanceOfAny(
                        BadSqlGrammarException.class, // hsqldb, postgres
                        TransientDataAccessResourceException.class // mysql
                );
    }

    @Test
    void iterationOverSubList() {
        list = new JdbcPagingList<>(jdbcTemplate, limitSqlAdapter, "SELECT * from foo",
                new ColumnMapRowMapper(), 3);
        list = list.subList(1, 4);
        assertThat(list).hasSize(3);
        int count = 0;
        for (Map<String, Object> map : list) {
            count++;
            assertThat(map).containsKey("name");
        }
        assertThat(count).isEqualTo(3);
    }

    @Test
    void iterationOverSubListWithSameSize() {
        list = new JdbcPagingList<>(jdbcTemplate, limitSqlAdapter, "SELECT * from foo",
                new ColumnMapRowMapper(), 3);
        list = list.subList(0, 5);
        assertThat(list).hasSize(5);
        int count = 0;
        for (Map<String, Object> map : list) {
            count++;
            assertThat(map).containsKey("name");
        }
        assertThat(count).isEqualTo(5);
    }

    @Test
    void subListExtendsBeyondSize() {
        list = new JdbcPagingList<>(jdbcTemplate, limitSqlAdapter, "SELECT * from foo",
                new ColumnMapRowMapper(), 3);
        assertThatExceptionOfType(IndexOutOfBoundsException.class).isThrownBy(() -> list.subList(1, 40));
    }

    @Test
    void subListFromDeletedElements() {
        list = new JdbcPagingList<>(jdbcTemplate, limitSqlAdapter, "SELECT * from foo",
                new ColumnMapRowMapper(), 3);
        jdbcTemplate.update("DELETE from foo where id>3");
        list = list.subList(1, list.size());
        assertThat(list).hasSize(5);
        int count = 0;
        for (Map<String, Object> map : list) {
            count++;
            assertThat(map).containsKey("name");
        }
        assertThat(count).isEqualTo(3); // count is less than original size estimate
    }
}
