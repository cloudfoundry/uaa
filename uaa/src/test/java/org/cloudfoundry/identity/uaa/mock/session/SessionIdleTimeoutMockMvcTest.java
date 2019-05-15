package org.cloudfoundry.identity.uaa.mock.session;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.web.SessionIdleTimeoutSetter;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.web.session.HttpSessionCreatedEvent;
import org.springframework.web.context.WebApplicationContext;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

@DefaultTestContext
class SessionIdleTimeoutMockMvcTest {
    private int timeout;
    private SessionIdleTimeoutSetter timeoutSetter;
    private WebApplicationContext webApplicationContext;

    @BeforeEach
    void setupForSessionIdleTimeout(
            @Autowired WebApplicationContext webApplicationContext) {
        this.webApplicationContext = webApplicationContext;

        timeoutSetter = webApplicationContext.getBean(SessionIdleTimeoutSetter.class);
        timeout = timeoutSetter.getTimeout();
    }

    @AfterEach
    void restoreTimeout() {
        timeoutSetter.setTimeout(timeout);
    }

    @Test
    void testSessionTimeout() {
        MockHttpSession session = new MockHttpSession();
        assertEquals(0, session.getMaxInactiveInterval());

        webApplicationContext.publishEvent(new HttpSessionCreatedEvent(session));

        assertEquals(timeout, session.getMaxInactiveInterval());
    }

    @Test
    void testSessionChangedTimeout() {
        timeoutSetter.setTimeout(300);
        MockHttpSession session = new MockHttpSession();
        assertEquals(0, session.getMaxInactiveInterval());

        webApplicationContext.publishEvent(new HttpSessionCreatedEvent(session));

        assertNotNull("session should exist", session);
        assertEquals(300, session.getMaxInactiveInterval());
    }
}
