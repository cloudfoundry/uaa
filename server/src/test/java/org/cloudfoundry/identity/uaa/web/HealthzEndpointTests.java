package org.cloudfoundry.identity.uaa.web;

import org.cloudfoundry.identity.uaa.health.HealthzEndpoint;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.lessThanOrEqualTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class HealthzEndpointTests {

    private static final long SLEEP_UPON_SHUTDOWN = 150;

    private HealthzEndpoint endpoint;
    private MockHttpServletResponse response;
    private Thread shutdownHook;

    @BeforeEach
    void setUp() {
        Runtime mockRuntime = mock(Runtime.class);
        endpoint = new HealthzEndpoint(SLEEP_UPON_SHUTDOWN, mockRuntime);
        response = new MockHttpServletResponse();

        ArgumentCaptor<Thread> threadArgumentCaptor = ArgumentCaptor.forClass(Thread.class);
        verify(mockRuntime).addShutdownHook(threadArgumentCaptor.capture());
        shutdownHook = threadArgumentCaptor.getValue();
    }

    @Test
    void getHealthz() {
        assertEquals("ok\n", endpoint.getHealthz(response));
    }

    @Test
    void shutdownSendsStopping() throws InterruptedException {
        long now = System.currentTimeMillis();
        shutdownHook.start();
        shutdownHook.join();
        assertEquals("stopping\n", endpoint.getHealthz(response));
        assertEquals(503, response.getStatus());
        long after = System.currentTimeMillis();
        assertThat(after, greaterThanOrEqualTo(now + SLEEP_UPON_SHUTDOWN));
    }

    @Nested
    class WithoutSleeping {
        @BeforeEach
        void setUp() {
            Runtime mockRuntime = mock(Runtime.class);
            endpoint = new HealthzEndpoint(-1, mockRuntime);
            response = new MockHttpServletResponse();

            ArgumentCaptor<Thread> threadArgumentCaptor = ArgumentCaptor.forClass(Thread.class);
            verify(mockRuntime).addShutdownHook(threadArgumentCaptor.capture());
            shutdownHook = threadArgumentCaptor.getValue();
        }

        @Test
        void shutdownWithoutSleep() throws InterruptedException {
            long now = System.currentTimeMillis();
            shutdownHook.start();
            shutdownHook.join();
            assertEquals("stopping\n", endpoint.getHealthz(response));
            assertEquals(503, response.getStatus());
            long after = System.currentTimeMillis();
            assertThat(after, lessThanOrEqualTo(now + SLEEP_UPON_SHUTDOWN));
        }
    }
}
