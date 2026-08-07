package org.cloudfoundry.identity.uaa.codestore;

import org.assertj.core.api.InstanceOfAssertFactories;
import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.test.TestUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.EmptyResultDataAccessException;

import javax.sql.DataSource;
import java.sql.SQLException;
import java.sql.Timestamp;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@WithDatabaseContext
class JdbcExpiringCodeStoreTest extends ExpiringCodeStoreTests {

    @Override
    @BeforeEach
    public void setUp() throws Exception {
        super.setUp();

        super.expiringCodeStore = new JdbcExpiringCodeStore(
                super.jdbcTemplate.getDataSource(),
                super.mockTimeService);

        // confirm that everything is clean prior to test.
        TestUtils.deleteFrom(jdbcTemplate, JdbcExpiringCodeStore.tableName);
    }

    @Test
    void databaseDown() throws Exception {
        DataSource mockDataSource = mock(DataSource.class);
        Mockito.when(mockDataSource.getConnection()).thenThrow(new SQLException());
        ((JdbcExpiringCodeStore) expiringCodeStore).setDataSource(mockDataSource);
        String data = "{}";
        Timestamp expiresAt = new Timestamp(System.currentTimeMillis() + 10000000);
        assertThatThrownBy(() -> expiringCodeStore.generateCode(data, expiresAt, null, IdentityZone.getUaaZoneId())).asInstanceOf(InstanceOfAssertFactories.throwable(DataAccessException.class));
    }

    @Test
    void expirationCleaner() {
        when(mockTimeService.getCurrentTimeMillis()).thenReturn(System.currentTimeMillis());
        jdbcTemplate.update(JdbcExpiringCodeStore.insert, "test", System.currentTimeMillis() - 1000, "{}", null, IdentityZone.getUaaZoneId());
        ((JdbcExpiringCodeStore) expiringCodeStore).cleanExpiredEntries();
        assertThatThrownBy(() -> jdbcTemplate.queryForObject(
                JdbcExpiringCodeStore.selectAllFields,
                new JdbcExpiringCodeStore.JdbcExpiringCodeMapper(),
                "test",
                IdentityZone.getUaaZoneId())).asInstanceOf(InstanceOfAssertFactories.throwable(EmptyResultDataAccessException.class));
    }

    @Override
    int countCodes() {
        return jdbcTemplate.queryForObject("select count(*) from expiring_code_store", Integer.class);
    }

    @Test
    void retrieveCodeConcurrently() throws Exception {
        String data = "{}";
        Timestamp expiresAt = new Timestamp(System.currentTimeMillis() + 60000);
        ExpiringCode generatedCode = expiringCodeStore.generateCode(data, expiresAt, null, IdentityZone.getUaaZoneId());

        int threadCount = 5;
        ExecutorService executorService = Executors.newFixedThreadPool(threadCount);
        CountDownLatch latch = new CountDownLatch(1);
        CountDownLatch doneLatch = new CountDownLatch(threadCount);

        AtomicInteger successCount = new AtomicInteger(0);
        AtomicInteger nullCount = new AtomicInteger(0);

        for (int i = 0; i < threadCount; i++) {
            executorService.submit(() -> {
                try {
                    latch.await();
                    ExpiringCode retrievedCode = expiringCodeStore.retrieveCode(generatedCode.getCode(), IdentityZone.getUaaZoneId());
                    if (retrievedCode != null) {
                        successCount.incrementAndGet();
                    } else {
                        nullCount.incrementAndGet();
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                } finally {
                    doneLatch.countDown();
                }
            });
        }

        latch.countDown();
        doneLatch.await(10, TimeUnit.SECONDS);

        assertThat(successCount.get()).isEqualTo(1);
        assertThat(nullCount.get()).isEqualTo(threadCount - 1);
    }

}