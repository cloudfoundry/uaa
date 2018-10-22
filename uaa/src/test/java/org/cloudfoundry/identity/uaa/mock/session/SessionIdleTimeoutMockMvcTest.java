package org.cloudfoundry.identity.uaa.mock.session;

import org.cloudfoundry.identity.uaa.TestSpringContext;
import org.cloudfoundry.identity.uaa.test.HoneycombAuditEventListenerRule;
import org.cloudfoundry.identity.uaa.web.SessionIdleTimeoutSetter;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.web.session.HttpSessionCreatedEvent;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.web.context.WebApplicationContext;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

@RunWith(SpringJUnit4ClassRunner.class)
@ActiveProfiles("default")
@WebAppConfiguration
@ContextConfiguration(classes = TestSpringContext.class)
public class SessionIdleTimeoutMockMvcTest {
    @Rule
    public HoneycombAuditEventListenerRule honeycombAuditEventListenerRule = new HoneycombAuditEventListenerRule();

    @Autowired
    public WebApplicationContext webApplicationContext;

    private int timeout;
    private SessionIdleTimeoutSetter timeoutSetter;

    @Before
    public void setupForSessionIdleTimeout() throws Exception {
        timeoutSetter = webApplicationContext.getBean(SessionIdleTimeoutSetter.class);
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

        webApplicationContext.publishEvent(new HttpSessionCreatedEvent(session));

        assertEquals(timeout, session.getMaxInactiveInterval());
    }


    @Test
    public void testSessionChangedTimeout() throws Exception {
        timeoutSetter.setTimeout(300);
        MockHttpSession session = new MockHttpSession();
        assertEquals(0, session.getMaxInactiveInterval());

        webApplicationContext.publishEvent(new HttpSessionCreatedEvent(session));

        assertNotNull("session should exist", session);
        assertEquals(300, session.getMaxInactiveInterval());
    }
}
