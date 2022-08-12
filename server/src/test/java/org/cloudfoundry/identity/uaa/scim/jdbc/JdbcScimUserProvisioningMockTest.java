package org.cloudfoundry.identity.uaa.scim.jdbc;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.cloudfoundry.identity.uaa.db.DatabaseUrlModifier;
import org.cloudfoundry.identity.uaa.db.Vendor;
import org.cloudfoundry.identity.uaa.resources.jdbc.JdbcPagingListFactory;
import org.cloudfoundry.identity.uaa.user.JdbcUaaUserDatabase;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;

class JdbcScimUserProvisioningMockTest {

    private JdbcScimUserProvisioning instance;
    private DatabaseUrlModifier databaseUrlModifier;
    private TimeService timeService;
    private JdbcTemplate jdbcTemplate;

    @BeforeEach
    void setUp() {
        jdbcTemplate = mock(JdbcTemplate.class);
        JdbcPagingListFactory pagingListFactory = mock(JdbcPagingListFactory.class);
        PasswordEncoder passwordEncoder = mock(PasswordEncoder.class);
        instance = new JdbcScimUserProvisioning(jdbcTemplate, pagingListFactory, passwordEncoder);

        databaseUrlModifier = mock(DatabaseUrlModifier.class);
        instance.setDatabaseUrlModifier(databaseUrlModifier);
        timeService = mock(TimeService.class);
        instance.setTimeService(timeService);
    }

    @Test
    void updateLastLogonTimePostgres() {
        when(databaseUrlModifier.getDatabaseType()).thenReturn(Vendor.postgresql);
        when(timeService.getCurrentTimeMillis()).thenReturn(4711L);

        instance.updateLastLogonTime("userid","zoneid");

        verify(jdbcTemplate).update(eq(JdbcUaaUserDatabase.DEFAULT_UPDATE_USER_LAST_LOGON_POSTGRES), eq(4711L), eq("userid"), eq("zoneid"));
    }

    @Test
    void updateLastLogonTimeMysql() {
        when(databaseUrlModifier.getDatabaseType()).thenReturn(Vendor.mysql);
        when(timeService.getCurrentTimeMillis()).thenReturn(4711L);

        instance.updateLastLogonTime("userid","zoneid");

        verify(jdbcTemplate).update(eq(JdbcUaaUserDatabase.DEFAULT_UPDATE_USER_LAST_LOGON), eq(4711L), eq("userid"), eq("zoneid"));
    }

    @Test
    void updateLastLogonTimeHsqldb() {
        when(databaseUrlModifier.getDatabaseType()).thenReturn(Vendor.mysql);
        when(timeService.getCurrentTimeMillis()).thenReturn(4711L);

        instance.updateLastLogonTime("userid","zoneid");

        verify(jdbcTemplate).update(eq(JdbcUaaUserDatabase.DEFAULT_UPDATE_USER_LAST_LOGON), eq(4711L), eq("userid"), eq("zoneid"));
    }

    @Test
    void updateLastLogonTimeUnknown() {
        when(databaseUrlModifier.getDatabaseType()).thenReturn(Vendor.unknown);
        when(timeService.getCurrentTimeMillis()).thenReturn(4711L);

        instance.updateLastLogonTime("userid","zoneid");

        verify(jdbcTemplate).update(eq(JdbcUaaUserDatabase.DEFAULT_UPDATE_USER_LAST_LOGON), eq(4711L), eq("userid"), eq("zoneid"));
    }

    @Test
    void updateLastLogonTimeNullModifier() {
        instance.setDatabaseUrlModifier(null);
        when(timeService.getCurrentTimeMillis()).thenReturn(4711L);

        instance.updateLastLogonTime("userid","zoneid");

        verify(jdbcTemplate).update(eq(JdbcUaaUserDatabase.DEFAULT_UPDATE_USER_LAST_LOGON), eq(4711L), eq("userid"), eq("zoneid"));
    }
}
