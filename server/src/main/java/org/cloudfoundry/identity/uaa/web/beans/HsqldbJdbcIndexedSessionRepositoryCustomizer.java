package org.cloudfoundry.identity.uaa.web.beans;

import org.springframework.session.config.SessionRepositoryCustomizer;
import org.springframework.session.jdbc.JdbcIndexedSessionRepository;

/**
 * HSQLDB counterpart to {@link org.springframework.session.jdbc.PostgreSqlJdbcIndexedSessionRepositoryCustomizer}
 * and {@link org.springframework.session.jdbc.MySqlJdbcIndexedSessionRepositoryCustomizer}: swaps the
 * default {@code INSERT} for {@code SPRING_SESSION_ATTRIBUTES} with an idempotent {@code MERGE}, so that
 * two concurrent requests both inserting a new attribute for the same session resolve as last-write-wins
 * instead of failing with {@link org.springframework.dao.DuplicateKeyException}.
 */
public class HsqldbJdbcIndexedSessionRepositoryCustomizer
        implements SessionRepositoryCustomizer<JdbcIndexedSessionRepository> {

    private static final String CREATE_SESSION_ATTRIBUTE_QUERY = """
            MERGE INTO %TABLE_NAME%_ATTRIBUTES AS T
            USING (VALUES (CAST(? AS CHAR(36)), CAST(? AS VARCHAR(200)), CAST(? AS BLOB)))
                AS S(SESSION_PRIMARY_ID, ATTRIBUTE_NAME, ATTRIBUTE_BYTES)
            ON T.SESSION_PRIMARY_ID = S.SESSION_PRIMARY_ID AND T.ATTRIBUTE_NAME = S.ATTRIBUTE_NAME
            WHEN MATCHED THEN UPDATE SET T.ATTRIBUTE_BYTES = S.ATTRIBUTE_BYTES
            WHEN NOT MATCHED THEN INSERT (SESSION_PRIMARY_ID, ATTRIBUTE_NAME, ATTRIBUTE_BYTES)
                VALUES (S.SESSION_PRIMARY_ID, S.ATTRIBUTE_NAME, S.ATTRIBUTE_BYTES)
            """;

    @Override
    public void customize(JdbcIndexedSessionRepository sessionRepository) {
        sessionRepository.setCreateSessionAttributeQuery(CREATE_SESSION_ATTRIBUTE_QUERY);
    }
}
