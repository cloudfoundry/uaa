package org.cloudfoundry.identity.uaa.scim.test;

import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.util.beans.DbUtils;
import org.springframework.jdbc.core.JdbcTemplate;

import java.sql.SQLException;
import java.util.Collections;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

public class TestUtils {

    public static void deleteFrom(
            final JdbcTemplate jdbcTemplate,
            final String... tables) {
        DbUtils dbUtils = new DbUtils();
        Stream.of(tables)
                .map(table -> {
                    try {
                        return "delete from " + dbUtils.getQuotedIdentifier(table, jdbcTemplate);
                    } catch (SQLException e) {
                        throw new RuntimeException(e);
                    }
                })
                .forEach(jdbcTemplate::update);
    }

    public static void assertNoSuchUser(
            final JdbcTemplate template,
            final String userId) {
        String sql = "select count(id) from users where id='%s'".formatted(
                userId);
        assertThat(template.queryForObject(sql, Integer.class)).isZero();
    }

    public static ScimUser scimUserInstance(String email) {
        ScimUser user = new ScimUser("", email, email, email);
        user.setPassword("password");
        ScimUser.Email em = new ScimUser.Email();
        em.setValue(email);
        user.setEmails(Collections.singletonList(em));
        return user;
    }

}
