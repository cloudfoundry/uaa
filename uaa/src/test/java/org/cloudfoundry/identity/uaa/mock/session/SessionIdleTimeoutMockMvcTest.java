package org.cloudfoundry.identity.uaa.mock.session;

import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.web.SessionIdleTimeoutSetter;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.web.session.HttpSessionCreatedEvent;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class SessionIdleTimeoutMockMvcTest extends InjectedMockContextTest {


    private int timeout;
    private SessionIdleTimeoutSetter timeoutSetter;

    @Before
    public void setupForSessionIdleTimeout() throws Exception {

        timeoutSetter = getWebApplicationContext().getBean(SessionIdleTimeoutSetter.class);
        timeout = timeoutSetter.getTimeout();
    }

    @After
    public void restoreTimeout() throws Exception {
        timeoutSetter.setTimeout(timeout);
    }

    @Test
    public void testSessionTimeout() throws Exception {

        MockHttpSession session = new MockHttpSession();
        assertEquals(0, session.getMaxInactiveInterval());


        getWebApplicationContext().publishEvent(new HttpSessionCreatedEvent(session));

        assertEquals(timeout, session.getMaxInactiveInterval());

    }


    @Test
    public void testSessionChangedTimeout() throws Exception {
        timeoutSetter.setTimeout(300);

        MockHttpSession session = new MockHttpSession();
        assertEquals(0, session.getMaxInactiveInterval());


        getWebApplicationContext().publishEvent(new HttpSessionCreatedEvent(session));

        assertNotNull("session should exist", session);
        assertEquals(300, session.getMaxInactiveInterval());

    }
}
