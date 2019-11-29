package org.cloudfoundry.identity.uaa.web.beans;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.session.Session;
import org.springframework.test.context.TestPropertySource;

import java.time.Duration;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DefaultTestContext
@TestPropertySource(properties = {
        "servlet.session.memory.cleanup.cron=* * * * * *"
})
class UaaMemorySessionConfigTest {

    @Test
    void sessionExpires(
            final @Autowired Map<String, Session> sessionMap
    ) throws Exception {
        String expiredSessionId = "expiredSessionId-" + UUID.randomUUID().toString();
        String validSessionId = "validSessionId-" + UUID.randomUUID().toString();

        final Session expiredSession = mock(Session.class);
        when(expiredSession.isExpired()).thenReturn(true);
        final Session validSession = mock(Session.class);
        when(validSession.isExpired()).thenReturn(false);

        sessionMap.put(expiredSessionId, expiredSession);
        sessionMap.put(validSessionId, validSession);

        Thread.sleep(Duration.ofSeconds(3).toMillis());

        assertNull(sessionMap.get(expiredSessionId));
        assertNotNull(sessionMap.get(validSessionId));
    }
}