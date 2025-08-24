package org.cloudfoundry.identity.uaa.health;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.mock.web.MockHttpServletResponse;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

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
    void getHealthz() throws SQLException {
        when(dataSource.getConnection()).thenThrow(new SQLException("DB is Down"));
        assertThat(endpoint.getHealthz(response)).isEqualTo("UAA running. Database failed to start.\n");
    }

    @Test
    void getHealthz_connectionSuccess() {
        endpoint.isDataSourceConnectionAvailable();
        assertThat(endpoint.getHealthz(response)).isEqualTo("ok\n");
    }

    @Test
    void getHealthz_connectionFailed() throws SQLException {
        when(statement.execute(anyString())).thenThrow(new SQLException());
        endpoint.isDataSourceConnectionAvailable();
        assertThat(endpoint.getHealthz(response)).isEqualTo("Database Connection failed.\n");
        assertThat(response.getStatus()).isEqualTo(503);
    }

    @Test
    void shutdownSendsStopping() throws InterruptedException {
        long now = System.currentTimeMillis();
        shutdownHook.start();
        shutdownHook.join();
        assertThat(endpoint.getHealthz(response)).isEqualTo("stopping\n");
        assertThat(response.getStatus()).isEqualTo(503);
        long after = System.currentTimeMillis();
        assertThat(after).isGreaterThanOrEqualTo(now + SLEEP_UPON_SHUTDOWN);
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
            assertThat(endpoint.getHealthz(response)).isEqualTo("stopping\n");
            assertThat(response.getStatus()).isEqualTo(503);
            long after = System.currentTimeMillis();
            assertThat(after).isLessThanOrEqualTo(now + SLEEP_UPON_SHUTDOWN);
        }
    }
}
