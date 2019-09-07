package org.cloudfoundry.identity.uaa.scim.test;

import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.Collections;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;

public class TestUtils {

    public static void deleteFrom(
            final JdbcTemplate jdbcTemplate,
            final String... tables) {
        Stream.of(tables)
                .map(table -> "delete from " + table)
                .forEach(jdbcTemplate::update);
    }

    public static void assertNoSuchUser(
            final JdbcTemplate template,
            final String userId) {
        String sql = String.format("select count(id) from users where id='%s'",
                userId);
        assertThat(template.queryForObject(sql, Integer.class), is(0));
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
