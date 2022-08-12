package org.cloudfoundry.identity.uaa.user;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.sql.SQLException;

import org.cloudfoundry.identity.uaa.db.DatabaseUrlModifier;
import org.cloudfoundry.identity.uaa.db.Vendor;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.cloudfoundry.identity.uaa.util.beans.DbUtils;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;

class JdbcUaaUserDatabaseMockTest {

    private JdbcUaaUserDatabase instance;
    private JdbcTemplate jdbcTemplate;
    private TimeService timeService;
    private DatabaseUrlModifier databaseUrlModifier;
    private IdentityZoneManager identityZoneManager;

    @BeforeEach
    void setUp() throws SQLException {
        boolean caseInsensitive = true;
        identityZoneManager = mock(IdentityZoneManager.class);
        DbUtils dbUtils = mock(DbUtils.class);

        jdbcTemplate = mock(JdbcTemplate.class);
        timeService = mock(TimeService.class);
        databaseUrlModifier = mock(DatabaseUrlModifier.class);

        instance = new JdbcUaaUserDatabase(jdbcTemplate, timeService, caseInsensitive, identityZoneManager, databaseUrlModifier, dbUtils);
    }

    @Test
    void updateLastLogonTimePostgres() {
        when(identityZoneManager.getCurrentIdentityZoneId()).thenReturn("zoneid");
        when(timeService.getCurrentTimeMillis()).thenReturn(4711L);
        when(databaseUrlModifier.getDatabaseType()).thenReturn(Vendor.postgresql);

        instance.updateLastLogonTime("userid");

        verify(jdbcTemplate).update(eq(JdbcUaaUserDatabase.DEFAULT_UPDATE_USER_LAST_LOGON_POSTGRES), eq(4711L), eq("userid"), eq("zoneid"));
    }

    @Test
    void updateLastLogonTimeMysql() {
        when(identityZoneManager.getCurrentIdentityZoneId()).thenReturn("zoneid");
        when(timeService.getCurrentTimeMillis()).thenReturn(4711L);
        when(databaseUrlModifier.getDatabaseType()).thenReturn(Vendor.mysql);

        instance.updateLastLogonTime("userid");

        verify(jdbcTemplate).update(eq(JdbcUaaUserDatabase.DEFAULT_UPDATE_USER_LAST_LOGON), eq(4711L), eq("userid"), eq("zoneid"));
    }

    @Test
    void updateLastLogonTimeHsqldb() {
        when(identityZoneManager.getCurrentIdentityZoneId()).thenReturn("zoneid");
        when(timeService.getCurrentTimeMillis()).thenReturn(4711L);
        when(databaseUrlModifier.getDatabaseType()).thenReturn(Vendor.hsqldb);

        instance.updateLastLogonTime("userid");

        verify(jdbcTemplate).update(eq(JdbcUaaUserDatabase.DEFAULT_UPDATE_USER_LAST_LOGON), eq(4711L), eq("userid"), eq("zoneid"));
    }

    @Test
    void updateLastLogonTimeUnknown() {
        when(identityZoneManager.getCurrentIdentityZoneId()).thenReturn("zoneid");
        when(timeService.getCurrentTimeMillis()).thenReturn(4711L);
        when(databaseUrlModifier.getDatabaseType()).thenReturn(Vendor.unknown);

        instance.updateLastLogonTime("userid");

        verify(jdbcTemplate).update(eq(JdbcUaaUserDatabase.DEFAULT_UPDATE_USER_LAST_LOGON), eq(4711L), eq("userid"), eq("zoneid"));
    }
}
