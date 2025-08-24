package org.cloudfoundry.identity.uaa.web.beans;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.session.Session;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class PurgeableSessionMapTest {
    private static final String SESSION_ID = "id";
    private PurgeableSessionMap sessions;

    @BeforeEach
    void setUp() {
        sessions = new PurgeableSessionMap();
    }

    @Test
    void doesNotDeleteActiveSessions() {
        sessions.put(SESSION_ID, createSession(SESSION_ID, false));

        sessions.purge();
        assertThat(sessions)
                .hasSize(1)
                .containsKey(SESSION_ID);
    }

    @Test
    void deletesActiveSessions() {
        sessions.put(SESSION_ID, createSession(SESSION_ID, true));

        sessions.purge();
        assertThat(sessions).isEmpty();
    }

    private Session createSession(String id, boolean expired) {
        Session session = mock(Session.class);
        when(session.getId()).thenReturn(id);
        when(session.isExpired()).thenReturn(expired);

        return session;
    }
}