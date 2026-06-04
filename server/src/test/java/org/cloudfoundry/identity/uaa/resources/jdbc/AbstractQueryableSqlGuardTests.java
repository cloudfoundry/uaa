package org.cloudfoundry.identity.uaa.resources.jdbc;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Focused tests for {@link AbstractQueryable#assertSafeGeneratedSql(String)} — the
 * defense-in-depth guard added to address CodeQL alert #27 ("Query built from
 * user-controlled sources"). These tests verify that unsafe constructs are rejected
 * and that typical generated SCIM filter fragments are accepted, so the guard cannot
 * be silently relaxed in the future.
 */
class AbstractQueryableSqlGuardTests {

    /**
     * Tiny subclass that exposes the {@code protected static} guard for direct testing.
     * No state, no behavior — just a hook to invoke the validator.
     */
    private static final class GuardHarness extends AbstractQueryable<Object> {
        private GuardHarness() {
            super((NamedParameterJdbcTemplate) null, (JdbcPagingListFactory) null, (RowMapper<Object>) null);
        }

        static void invoke(String sqlFragment) {
            assertSafeGeneratedSql(sqlFragment);
        }

        @Override
        protected String getBaseSqlQuery() {
            return "";
        }

        @Override
        protected String getTableName() {
            return "";
        }

        @Override
        protected void validateOrderBy(String orderBy) {
            // no-op
        }
    }

    // ---------- Empty / blank fragments ----------

    @ParameterizedTest
    @ValueSource(strings = {"", "   ", "\t", "\n"})
    void rejectsEmptyOrBlankFragments(String fragment) {
        assertThatThrownBy(() -> GuardHarness.invoke(fragment))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("empty SQL fragment");
    }

    @Test
    void rejectsNullFragment() {
        assertThatThrownBy(() -> GuardHarness.invoke(null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("empty SQL fragment");
    }

    // ---------- Statement separators / comment tokens ----------

    @ParameterizedTest
    @ValueSource(strings = {
            "username = :__value_0; drop table users",        // statement separator
            "username = :__value_0 -- and 1=1",                // ANSI line comment
            "username = :__value_0 # mysql line comment",      // MySQL # line comment
            "username = :__value_0 /* block comment */",       // start of block comment
            "username = :__value_0 */ trailing"                // end of block comment
    })
    void rejectsDisallowedTokens(String fragment) {
        assertThatThrownBy(() -> GuardHarness.invoke(fragment))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("disallowed SQL token");
    }

    // ---------- Leading DML/DDL clauses (the keyword guard) ----------

    @ParameterizedTest
    @ValueSource(strings = {
            "select * from users",
            "SELECT * from users",
            "insert into users values (1)",
            "update users set x = 1",
            "delete from users",
            "drop table users",
            "alter table users add column x",
            "create table foo(x int)",
            "truncate users",
            "merge into users",
            "union select 1",
            "with x as (select 1) select * from x",
            "grant all to public",
            "revoke select on users",
            "exec something",
            "execute something",
            "call proc()",
            "replace into users",
            "rename table users to bar",
            "comment on column foo is 'x'"
    })
    void rejectsLeadingDmlDdlKeywordWithSpace(String fragment) {
        assertThatThrownBy(() -> GuardHarness.invoke(fragment))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("unexpected SQL clause");
    }

    /**
     * Bypasses raised by Copilot review: the prior implementation only blocked
     * "{keyword} " (literal space). These variants must also be rejected.
     */
    @ParameterizedTest
    @ValueSource(strings = {
            "SELECT\tfoo",   // tab
            "SELECT\nfoo",   // newline
            "SELECT\rfoo",   // carriage return
            "SELECT\ffoo",   // form feed
            "select(1)",     // open paren, no whitespace
            "  select foo",  // leading whitespace before keyword
            "UPDATE\tusers", // mixed-case + tab
            "Drop(table)"    // mixed-case + paren
    })
    void rejectsKeywordFollowedByWhitespaceVariantsOrParen(String fragment) {
        assertThatThrownBy(() -> GuardHarness.invoke(fragment))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("unexpected SQL clause");
    }

    /**
     * Parenthesis-wrapped bypass raised by Copilot review: a fragment like
     * "(select 1)" or "((select 1))" must be rejected — leading whitespace and
     * "(" are stripped before the DML/DDL keyword check.
     */
    @ParameterizedTest
    @ValueSource(strings = {
            "(select 1)",
            "((select 1))",
            "( select 1 )",
            "(\tselect 1)",
            "( ( select 1 ) )",
            " (select 1) ",
            "((((delete from users))))",
            "(UPDATE users set x=1)",
            "(DROP table users)",
            "(union select 1)"
    })
    void rejectsParenthesisWrappedKeyword(String fragment) {
        assertThatThrownBy(() -> GuardHarness.invoke(fragment))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("unexpected SQL clause");
    }

    // ---------- Typical generated SCIM filter fragments are accepted ----------

    @ParameterizedTest
    @ValueSource(strings = {
            // shapes produced by SimpleSearchQueryConverter — values are bound parameters
            "username = :__value_0",
            "username = :__value_0 and origin = :__value_1",
            "(username = :__value_0 or origin = :__value_1) and active = :__value_2",
            "lower(username) = lower(:__value_0)",
            "username = :__value_0 order by created desc",
            // an attribute that happens to start with a keyword-prefix (must not be rejected)
            "selectable = :__value_0",
            "createdby = :__value_0"
    })
    void acceptsTypicalGeneratedFragments(String fragment) {
        assertThatCode(() -> GuardHarness.invoke(fragment)).doesNotThrowAnyException();
    }
}
