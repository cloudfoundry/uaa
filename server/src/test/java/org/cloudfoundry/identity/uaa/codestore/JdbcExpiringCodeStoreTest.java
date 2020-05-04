package org.cloudfoundry.identity.uaa.codestore;

import org.cloudfoundry.identity.uaa.test.TestUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.EmptyResultDataAccessException;

import javax.sql.DataSource;
import java.sql.SQLException;
import java.sql.Timestamp;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class JdbcExpiringCodeStoreTest extends ExpiringCodeStoreTests {

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();

        super.expiringCodeStore = new JdbcExpiringCodeStore(
                jdbcTemplate.getDataSource(),
                super.mockTimeService);

        // confirm that everything is clean prior to test.
        TestUtils.deleteFrom(jdbcTemplate, JdbcExpiringCodeStore.tableName);
    }

    @Test
    public void testDatabaseDown() throws Exception {
        DataSource mockDataSource = mock(DataSource.class);
        Mockito.when(mockDataSource.getConnection()).thenThrow(new SQLException());
        ((JdbcExpiringCodeStore) expiringCodeStore).setDataSource(mockDataSource);
        String data = "{}";
        Timestamp expiresAt = new Timestamp(System.currentTimeMillis() + 10000000);
        assertThrows(DataAccessException.class,
                () -> expiringCodeStore.generateCode(data, expiresAt, null, IdentityZoneHolder.get().getId()));
    }

    @Test
    public void testExpirationCleaner() {
        when(mockTimeService.getCurrentTimeMillis()).thenReturn(System.currentTimeMillis());
        jdbcTemplate.update(JdbcExpiringCodeStore.insert, "test", System.currentTimeMillis() - 1000, "{}", null, IdentityZoneHolder.get().getId());
        ((JdbcExpiringCodeStore) expiringCodeStore).cleanExpiredEntries();
        assertThrows(EmptyResultDataAccessException.class,
                () -> jdbcTemplate.queryForObject(
                        JdbcExpiringCodeStore.selectAllFields,
                        new JdbcExpiringCodeStore.JdbcExpiringCodeMapper(),
                        "test",
                        IdentityZoneHolder.get().getId()));
    }

}