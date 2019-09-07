package org.cloudfoundry.identity.uaa.web;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.web.session.HttpSessionCreatedEvent;

import javax.servlet.http.HttpSession;

import static org.mockito.Mockito.*;

public class SessionIdleTimeoutSetterTest {
    SessionIdleTimeoutSetter listener;
    private HttpSessionCreatedEvent event;
    private HttpSession session;

    @Before
    public void setUp() throws Exception {
        event = mock(HttpSessionCreatedEvent.class);
        session = mock(HttpSession.class);
        when(event.getSession()).thenReturn(session);

        listener = new SessionIdleTimeoutSetter();

    }

    @Test
    public void testDefaultTimeout() {

        listener.onApplicationEvent(event);

        verify(session, times(1)).setMaxInactiveInterval(30 * 60);
    }

    @Test
    public void testNonDefaultTimeout() {

        listener.setTimeout(15 * 60);

        listener.onApplicationEvent(event);

        verify(session, times(1)).setMaxInactiveInterval(15 * 60);
    }

    @After
    public void tearDown() throws Exception {
    }

}