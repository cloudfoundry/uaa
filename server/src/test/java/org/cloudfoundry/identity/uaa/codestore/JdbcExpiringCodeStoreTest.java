package org.cloudfoundry.identity.uaa.codestore;

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

import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
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
        assertThatExceptionOfType(DataAccessException.class).isThrownBy(() -> expiringCodeStore.generateCode(data, expiresAt, null, IdentityZone.getUaaZoneId()));
    }

    @Test
    void expirationCleaner() {
        when(mockTimeService.getCurrentTimeMillis()).thenReturn(System.currentTimeMillis());
        jdbcTemplate.update(JdbcExpiringCodeStore.insert, "test", System.currentTimeMillis() - 1000, "{}", null, IdentityZone.getUaaZoneId());
        ((JdbcExpiringCodeStore) expiringCodeStore).cleanExpiredEntries();
        assertThatExceptionOfType(EmptyResultDataAccessException.class).isThrownBy(() -> jdbcTemplate.queryForObject(
                JdbcExpiringCodeStore.selectAllFields,
                new JdbcExpiringCodeStore.JdbcExpiringCodeMapper(),
                "test",
                IdentityZone.getUaaZoneId()));
    }

    @Override
    int countCodes() {
        return jdbcTemplate.queryForObject("select count(*) from expiring_code_store", Integer.class);
    }

}