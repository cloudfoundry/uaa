package org.cloudfoundry.identity.uaa.db;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.web.beans.UaaJdbcSessionConfig;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;
import org.springframework.session.jdbc.JdbcIndexedSessionRepository;
import org.springframework.test.context.TestPropertySource;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * Reproduces the production race where two concurrent requests sharing the same
 * JSESSIONID both see a session attribute as new, both mark their delta as {@code ADDED},
 * and both call {@code save()} — the second {@code INSERT INTO SPRING_SESSION_ATTRIBUTES}
 * fails with {@link org.springframework.dao.DuplicateKeyException}.
 *
 * <p>Loads the real UAA Spring context with {@code servlet.session-store=database}, so the
 * {@link JdbcIndexedSessionRepository} under test is the one wired up by
 * {@link UaaJdbcSessionConfig} — including the vendor-specific upsert customizer. The CI
 * matrix runs this test against hsqldb, mysql, and postgresql, exercising all three SQL
 * dialects of the fix.
 *
 * <p>The race is fully deterministic at the repository level (the delta {@code ADDED}
 * vs {@code UPDATED} decision is taken purely from each {@code JdbcSession}'s local
 * {@code MapSession} delegate, populated only at {@code findById} time), so no threads
 * are required to reproduce it.
 */
@DefaultTestContext
@TestPropertySource(properties = "servlet.session-store=database")
class JdbcSessionConcurrentWriteMockMvcTest {

    private static final String SPRING_SECURITY_CONTEXT = "SPRING_SECURITY_CONTEXT";

    @Autowired
    private SessionRepository<?> sessionRepository;

    private String createdSessionId;

    @AfterEach
    void cleanUp() {
        if (createdSessionId != null) {
            sessionRepository.deleteById(createdSessionId);
        }
    }

    /**
     * Two requests share one JSESSIONID:
     * <ol>
     *   <li>Both call {@code findById} before either has written — neither delegate
     *       has {@code SPRING_SECURITY_CONTEXT}, so each marks its delta as {@code ADDED}.</li>
     *   <li>Request A's {@code save()} inserts the attribute row — succeeds.</li>
     *   <li>Request B's {@code save()} inserts the same attribute row — before the fix,
     *       this threw {@code DuplicateKeyException}; with the per-vendor upsert customizer
     *       wired in, it resolves as last-write-wins.</li>
     * </ol>
     */
    @Test
    void concurrentInsertsForSameAttributeAreIdempotent() {
        runRace(sessionRepository);
    }

    /**
     * Wildcard-capture helper. {@link SessionRepository} is wired in as
     * {@code SessionRepository<?>} (the concrete session type is package-private), so we
     * capture the wildcard as a method type parameter to keep {@code createSession}/
     * {@code save}/{@code findById} type-aligned.
     */
    private <S extends Session> void runRace(SessionRepository<S> repo) {
        S created = repo.createSession();
        repo.save(created);
        createdSessionId = created.getId();

        S requestA = repo.findById(createdSessionId);
        S requestB = repo.findById(createdSessionId);
        assertThat(requestA).as("Session A should load").isNotNull();
        assertThat(requestB).as("Session B should load").isNotNull();

        requestA.setAttribute(SPRING_SECURITY_CONTEXT, securityContextFor("user-A"));
        requestB.setAttribute(SPRING_SECURITY_CONTEXT, securityContextFor("user-B"));

        repo.save(requestA);

        assertThatCode(() -> repo.save(requestB))
                .as("Concurrent INSERTs for the same (session_primary_id, attribute_name) "
                        + "should resolve as an UPSERT (last write wins), not fail with DuplicateKeyException")
                .doesNotThrowAnyException();

        S reloaded = repo.findById(createdSessionId);
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
