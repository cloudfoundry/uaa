package org.cloudfoundry.identity.uaa.web.tomcat;

import org.apache.catalina.Container;
import org.apache.catalina.Engine;
import org.apache.catalina.Lifecycle;
import org.apache.catalina.LifecycleEvent;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.LifecycleState;
import org.apache.catalina.Server;
import org.apache.catalina.Service;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class UaaStartupFailureListenerTest {
    @Nested
    class ByDefault {
        private Server server;
        private UaaStartupFailureListener listener;

        @BeforeEach
        void setUp() {
            listener = new UaaStartupFailureListener();
            server = mockServer(mockService(LifecycleState.STARTED));
        }

        @Test
        void doesNotStopTheServer() throws LifecycleException {
            listener.lifecycleEvent(mockLifecycleEvent(server, Lifecycle.AFTER_START_EVENT));
            verify(server, times(0)).start();
            verify(server, times(0)).destroy();
        }
    }

    @Nested
    class WhenInitializationFails {
        private Server server;
        private UaaStartupFailureListener listener;

        @BeforeEach
        void setUp() {
            listener = new UaaStartupFailureListener();
            server = mockServer(mockService(LifecycleState.FAILED));
        }

        @Test
        void stopsTheServer() throws LifecycleException {
            listener.lifecycleEvent(mockLifecycleEvent(server, Lifecycle.AFTER_START_EVENT));
            verify(server, times(1)).stop();
            verify(server, times(1)).destroy();
        }

        @Test
        void rethrowsAnyExceptions() throws LifecycleException {
            doThrow(new LifecycleException()).when(server).stop();
            assertThatExceptionOfType(RuntimeException.class).isThrownBy(() -> listener.lifecycleEvent(mockLifecycleEvent(server, Lifecycle.AFTER_START_EVENT)));
            verify(server, times(1)).stop();
            verify(server, times(0)).destroy();
        }
    }

    private LifecycleEvent mockLifecycleEvent(Server server, String type) {
        LifecycleEvent mockEvent = mock(LifecycleEvent.class);
        when(mockEvent.getType()).thenReturn(type);
        when(mockEvent.getLifecycle()).thenReturn(server);
        return mockEvent;
    }

    private Server mockServer(Service service) {
        Server mockServer = mock(Server.class);
        when(mockServer.findServices()).thenReturn(new Service[]{service});
        return mockServer;
    }

    private Service mockService(LifecycleState state) {
        Engine mockContainer = mock(Engine.class);
        when(mockContainer.getState()).thenReturn(state);
        when(mockContainer.findChildren()).thenReturn(new Container[]{});

        Service mockService = mock(Service.class);
        when(mockService.getContainer()).thenReturn(mockContainer);

        return mockService;
    }
}
