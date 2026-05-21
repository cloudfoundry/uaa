package org.cloudfoundry.identity.uaa.web.beans;

import java.util.Collections;
import javax.sql.DataSource;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.db.beans.DatabaseProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;
import org.springframework.session.config.SessionRepositoryCustomizer;
import org.springframework.session.jdbc.JdbcIndexedSessionRepository;
import org.springframework.session.jdbc.MySqlJdbcIndexedSessionRepositoryCustomizer;
import org.springframework.session.jdbc.PostgreSqlJdbcIndexedSessionRepositoryCustomizer;
import org.springframework.transaction.support.TransactionTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * Reproduces the production race where two concurrent requests sharing the same
 * JSESSIONID both see a session attribute as new, both mark their delta as {@code ADDED},
 * and both call {@code save()} — the second {@code INSERT INTO SPRING_SESSION_ATTRIBUTES}
 * fails with {@link org.springframework.dao.DuplicateKeyException}.
 *
 * <p>The race is fully deterministic at the repository level (the delta {@code ADDED}
 * vs {@code UPDATED} decision is taken purely from each {@code JdbcSession}'s local
 * {@code MapSession} delegate, populated only at {@code findById} time), so no
 * threads are required to reproduce it.
 *
 * <p>Runs against whichever DB the CI matrix selects via {@code spring.profiles.active}
 * (hsqldb, mysql, postgresql) and applies the matching upsert customizer — the same one
 * {@link UaaJdbcSessionConfig} wires up in production — so all three SQL dialects are
 * covered.
 */
@WithDatabaseContext
class JdbcSessionConcurrentWriteTest {

    private static final String SPRING_SECURITY_CONTEXT = "SPRING_SECURITY_CONTEXT";

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private DataSource dataSource;

    @Autowired
    private DatabaseProperties databaseProperties;

    @SuppressWarnings("rawtypes")
    private SessionRepository repository;

    @BeforeEach
    void setUp() {
        TransactionTemplate transactionTemplate =
                new TransactionTemplate(new DataSourceTransactionManager(dataSource));
        JdbcIndexedSessionRepository jdbcRepository =
                new JdbcIndexedSessionRepository(jdbcTemplate, transactionTemplate);
        // Disable the background cleanup scheduler — we never call afterPropertiesSet,
        // but be explicit so future changes don't accidentally start it.
        jdbcRepository.setCleanupCron("-");
        // Apply the same upsert SQL that UaaJdbcSessionConfig wires up in production,
        // chosen by the active DB platform so this test exercises the real fix on
        // whichever database the CI matrix is running against (hsqldb/mysql/postgresql).
        customizerFor(databaseProperties).customize(jdbcRepository);
        this.repository = jdbcRepository;
    }

    private static SessionRepositoryCustomizer<JdbcIndexedSessionRepository> customizerFor(
            DatabaseProperties databaseProperties) {
        return switch (databaseProperties.getDatabasePlatform()) {
            case POSTGRESQL -> new PostgreSqlJdbcIndexedSessionRepositoryCustomizer();
            case MYSQL -> new MySqlJdbcIndexedSessionRepositoryCustomizer();
            case HSQLDB -> new HsqldbJdbcIndexedSessionRepositoryCustomizer();
        };
    }

    /**
     * Two requests share one JSESSIONID:
     * <ol>
     *   <li>Both call {@code findById} before either has written — neither delegate
     *       has {@code SPRING_SECURITY_CONTEXT}, so each marks its delta as {@code ADDED}.</li>
     *   <li>Request A's {@code save()} inserts the attribute row — succeeds.</li>
     *   <li>Request B's {@code save()} insert the same attribute row — currently
     *       throws {@code DuplicateKeyException}.</li>
     * </ol>
     */
    @Test
    @SuppressWarnings("unchecked")
    void concurrentRequestsAddingSameAttributeShouldNotCollide() {
        Session created = repository.createSession();
        repository.save(created);
        String sessionId = created.getId();

        Session requestA = repository.findById(sessionId);
        Session requestB = repository.findById(sessionId);
        assertThat(requestA).as("Session A should load").isNotNull();
        assertThat(requestB).as("Session B should load").isNotNull();

        requestA.setAttribute(SPRING_SECURITY_CONTEXT, securityContextFor("user-A"));
        requestB.setAttribute(SPRING_SECURITY_CONTEXT, securityContextFor("user-B"));

        repository.save(requestA);

        assertThatCode(() -> repository.save(requestB))
                .as("Concurrent INSERTs for the same (session_primary_id, attribute_name) "
                        + "should resolve as an UPSERT (last write wins), not fail with DuplicateKeyException")
                .doesNotThrowAnyException();

        Session reloaded = repository.findById(sessionId);
        assertThat(reloaded).isNotNull();
        SecurityContext stored = reloaded.getAttribute(SPRING_SECURITY_CONTEXT);
        assertThat(stored).isNotNull();
        assertThat(stored.getAuthentication().getName())
                .as("Last write should win")
                .isEqualTo("user-B");
    }

    private static SecurityContext securityContextFor(String username) {
        return new SecurityContextImpl(
                new UsernamePasswordAuthenticationToken(username, "pw", Collections.emptyList()));
    }
}
