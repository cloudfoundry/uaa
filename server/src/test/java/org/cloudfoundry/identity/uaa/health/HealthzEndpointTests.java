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
        String healthCheckStatement = "SELECT 1 FROM identity_zone;";
        endpoint = new HealthzEndpoint(SLEEP_UPON_SHUTDOWN, mockRuntime, dataSource, healthCheckStatement);
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
    void getHealthz_connectionSuccess() throws SQLException {
        endpoint.isDataSourceConnectionAvailable();
        assertThat(endpoint.getHealthz(response)).isEqualTo("ok\n");
        verify(statement).execute("SELECT 1 FROM identity_zone;");
    }

    @Test
    void getHealthz_connectionFailed() throws SQLException {
        when(statement.execute(anyString())).thenThrow(new SQLException());
        endpoint.isDataSourceConnectionAvailable();
        assertThat(endpoint.getHealthz(response)).isEqualTo("Database Connection failed.\n");
        assertThat(response.getStatus()).isEqualTo(503);
    }

    @Test
    void getHealthz_withChangedStatement() throws SQLException {
        Runtime mockRuntime = mock(Runtime.class);
        DataSource changedDataSource = mock(DataSource.class);
        Connection changedConnection = mock(Connection.class);
        Statement changeStatement = mock(Statement.class);
        when(changedDataSource.getConnection()).thenReturn(changedConnection);
        when(changedConnection.createStatement()).thenReturn(changeStatement);

        String changedHealthCheckStatement = "SELECT 1;";
        HealthzEndpoint changedEndpoint = new HealthzEndpoint(SLEEP_UPON_SHUTDOWN, mockRuntime, changedDataSource, changedHealthCheckStatement);
        MockHttpServletResponse changedResponse = new MockHttpServletResponse();

        changedEndpoint.isDataSourceConnectionAvailable();
        assertThat(changedEndpoint.getHealthz(changedResponse)).isEqualTo("ok\n");
        verify(changeStatement).execute(changedHealthCheckStatement);
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
            String healthCheckStatement = "SELECT 1 FROM identity_zone;";
            endpoint = new HealthzEndpoint(-1, mockRuntime, dataSource, healthCheckStatement);
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
