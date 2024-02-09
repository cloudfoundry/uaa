package org.cloudfoundry.identity.uaa.health;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.lessThanOrEqualTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import javax.sql.DataSource;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.mock.web.MockHttpServletResponse;

class HealthzEndpointTests {

    private static final long SLEEP_UPON_SHUTDOWN = 150;

    private HealthzEndpoint endpoint;
    private MockHttpServletResponse response;
    private Thread shutdownHook;
    private DataSource dataSource;
    private Connection connection;
    private Statement statement;

    @BeforeEach
    void setUp() throws SQLException {
        Runtime mockRuntime = mock(Runtime.class);
        dataSource = mock(DataSource.class);
        connection = mock(Connection.class);
        statement = mock(Statement.class);
        when(dataSource.getConnection()).thenReturn(connection);
        when(connection.createStatement()).thenReturn(statement);
        endpoint = new HealthzEndpoint(SLEEP_UPON_SHUTDOWN, mockRuntime, dataSource);
        response = new MockHttpServletResponse();

        ArgumentCaptor<Thread> threadArgumentCaptor = ArgumentCaptor.forClass(Thread.class);
        verify(mockRuntime).addShutdownHook(threadArgumentCaptor.capture());
        shutdownHook = threadArgumentCaptor.getValue();
    }

    @Test
    void getHealthz() {
        assertEquals("UAA running. Database status unknown.\n", endpoint.getHealthz(response));
    }

    @Test
    void getHealthz_connectionSuccess() {
        endpoint.isDataSourceConnectionAvailable();
        assertEquals("ok\n", endpoint.getHealthz(response));
    }
    @Test
    void getHealthz_connectionFailed() throws SQLException {
        when(statement.execute(anyString())).thenThrow(new SQLException());
        endpoint.isDataSourceConnectionAvailable();
        assertEquals("Database Connection failed.\n", endpoint.getHealthz(response));
        assertEquals(503, response.getStatus());
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
            DataSource dataSource = mock(DataSource.class);
            endpoint = new HealthzEndpoint(-1, mockRuntime, dataSource);
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
