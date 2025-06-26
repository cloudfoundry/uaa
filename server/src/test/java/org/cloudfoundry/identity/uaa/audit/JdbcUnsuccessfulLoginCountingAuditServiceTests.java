package org.cloudfoundry.identity.uaa.audit;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.util.ReflectionTestUtils;

import java.sql.Timestamp;
import java.util.EnumSet;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.audit.AuditEventType.ClientAuthenticationFailure;
import static org.cloudfoundry.identity.uaa.audit.AuditEventType.PasswordChangeSuccess;
import static org.cloudfoundry.identity.uaa.audit.AuditEventType.UserAccountUnlockedEvent;
import static org.cloudfoundry.identity.uaa.audit.AuditEventType.UserAuthenticationFailure;
import static org.cloudfoundry.identity.uaa.audit.AuditEventType.UserAuthenticationSuccess;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@WithDatabaseContext
class JdbcUnsuccessfulLoginCountingAuditServiceTests {

    private JdbcUnsuccessfulLoginCountingAuditService auditService;

    private String authDetails;
    private JdbcTemplate template;

    private TimeService mockTimeService;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @BeforeEach
    void createService() {
        template = spy(jdbcTemplate);
        mockTimeService = mock(TimeService.class);
        auditService = new JdbcUnsuccessfulLoginCountingAuditService(template, mockTimeService);
        jdbcTemplate.execute("DELETE FROM sec_audit WHERE principal_id='1' or principal_id='clientA' or principal_id='clientB'");
        authDetails = "1.1.1.1";
    }

    @Test
    void userAuthenticationFailureAuditSucceeds() throws Exception {
        auditService.log(getAuditEvent(UserAuthenticationFailure, "1", "joe"), getAuditEvent(UserAuthenticationFailure, "1", "joe").getIdentityZoneId());
        Thread.sleep(100);
        auditService.log(getAuditEvent(UserAuthenticationFailure, "1", "joe"), getAuditEvent(UserAuthenticationFailure, "1", "joe").getIdentityZoneId());
        List<AuditEvent> events = auditService.find("1", 0, IdentityZone.getUaaZoneId());
        assertThat(events).hasSize(2);
        assertThat(events.getFirst().getPrincipalId()).isEqualTo("1");
        assertThat(events.getFirst().getData()).isEqualTo("joe");
        assertThat(events.getFirst().getOrigin()).isEqualTo("1.1.1.1");
    }

    @Test
    void userAuthenticationFailureDeletesOldData() {
        long now = System.currentTimeMillis();
        when(mockTimeService.getCurrentTimeMillis()).thenReturn(now);
        auditService.log(getAuditEvent(UserAuthenticationFailure, "1", "joe"), getAuditEvent(UserAuthenticationFailure, "1", "joe").getIdentityZoneId());
        assertThat(jdbcTemplate.queryForObject("select count(*) from sec_audit where principal_id='1'", Integer.class)).isOne();
        ReflectionTestUtils.invokeMethod(ReflectionTestUtils.getField(auditService, "lastDelete"), "set", 0l);
        // Set the created column to 25 hours past
        jdbcTemplate.update("update sec_audit set created=?", new Timestamp(now - 25 * 3600 * 1000));
        auditService.log(getAuditEvent(UserAuthenticationFailure, "1", "joe"), getAuditEvent(UserAuthenticationFailure, "1", "joe").getIdentityZoneId());
        assertThat(jdbcTemplate.queryForObject("select count(*) from sec_audit where principal_id='1'", Integer.class)).isOne();
    }

    @Test
    void delete_happens_single_thread_on_intervals() {
        long now = System.currentTimeMillis();
        when(mockTimeService.getCurrentTimeMillis()).thenReturn(now);
        auditService.log(getAuditEvent(UserAuthenticationFailure, "1", "joe"), getAuditEvent(UserAuthenticationFailure, "1", "joe").getIdentityZoneId());
        assertThat(jdbcTemplate.queryForObject("select count(*) from sec_audit where principal_id='1'", Integer.class)).isOne();
        // Set the created column to 25 hours past
        jdbcTemplate.update("update sec_audit set created=?", new Timestamp(now - 25 * 3600 * 1000));
        int count = 5;
        for (int i = 0; i < count; i++) {
            auditService.log(getAuditEvent(UserAuthenticationFailure, "1", "joe"), getAuditEvent(UserAuthenticationFailure, "1", "joe").getIdentityZoneId());
        }
        assertThat(jdbcTemplate.queryForObject("select count(*) from sec_audit where principal_id='1'", Integer.class)).isEqualTo(count + 1);
        ArgumentCaptor<String> queries = ArgumentCaptor.forClass(String.class);
        verify(template, times(1)).update(queries.capture(), any(Timestamp.class));
    }

    @Test
    void periodic_delete_works() {
        when(mockTimeService.getCurrentTimeMillis()).thenReturn(System.currentTimeMillis());

        for (int i = 0; i < 5; i++) {
            auditService.periodicDelete();
        }
        verify(template, times(1)).update(anyString(), any(Timestamp.class));
        // 30 seconds has passed
        when(mockTimeService.getCurrentTimeMillis()).thenReturn(System.currentTimeMillis() + (31 * 1000));
        reset(template);
        for (int i = 0; i < 5; i++) {
            auditService.periodicDelete();
        }
        verify(template, times(1)).update(anyString(), any(Timestamp.class));
    }

    @Test
    void userAuthenticationSuccessResetsData() {
        auditService.log(getAuditEvent(UserAuthenticationFailure, "1", "joe"), getAuditEvent(UserAuthenticationFailure, "1", "joe").getIdentityZoneId());
        assertThat(jdbcTemplate.queryForObject("select count(*) from sec_audit where principal_id='1'", Integer.class)).isOne();
        auditService.log(getAuditEvent(UserAuthenticationSuccess, "1", "joe"), getAuditEvent(UserAuthenticationSuccess, "1", "joe").getIdentityZoneId());
        assertThat(jdbcTemplate.queryForObject("select count(*) from sec_audit where principal_id='1'", Integer.class)).isZero();
    }

    @Test
    void userPasswordChangeSuccessResetsData() {
        auditService.log(getAuditEvent(UserAuthenticationFailure, "1", "joe"), getAuditEvent(UserAuthenticationFailure, "1", "joe").getIdentityZoneId());
        assertThat(jdbcTemplate.queryForObject("select count(*) from sec_audit where principal_id='1'", Integer.class)).isOne();
        auditService.log(getAuditEvent(PasswordChangeSuccess, "1", "joe"), getAuditEvent(PasswordChangeSuccess, "1", "joe").getIdentityZoneId());
        assertThat(jdbcTemplate.queryForObject("select count(*) from sec_audit where principal_id='1'", Integer.class)).isZero();
    }

    @Test
    void findMethodOnlyReturnsEventsWithinRequestedPeriod() {
        long now = System.currentTimeMillis();
        when(mockTimeService.getCurrentTimeMillis()).thenReturn(now);
        auditService.log(getAuditEvent(UserAuthenticationFailure, "1", "joe"), getAuditEvent(UserAuthenticationFailure, "1", "joe").getIdentityZoneId());
        auditService.log(getAuditEvent(ClientAuthenticationFailure, "client", "testman"), getAuditEvent(ClientAuthenticationFailure, "client", "testman").getIdentityZoneId());
        // Set the created column to 2 hour past
        jdbcTemplate.update("update sec_audit set created=?", new Timestamp(now - 2 * 3600 * 1000));
        auditService.log(getAuditEvent(UserAuthenticationFailure, "1", "joe"), getAuditEvent(UserAuthenticationFailure, "1", "joe").getIdentityZoneId());
        auditService.log(getAuditEvent(UserAuthenticationFailure, "2", "joe"), getAuditEvent(UserAuthenticationFailure, "2", "joe").getIdentityZoneId());
        auditService.log(getAuditEvent(ClientAuthenticationFailure, "client", "testman"), getAuditEvent(ClientAuthenticationFailure, "client", "testman").getIdentityZoneId());
        auditService.log(getAuditEvent(ClientAuthenticationFailure, "otherclient", "testman"), getAuditEvent(ClientAuthenticationFailure, "otherclient", "testman").getIdentityZoneId());
        // Find events within last 2 mins
        List<AuditEvent> userEvents = auditService.find("1", now - 2 * 60 * 1000, IdentityZone.getUaaZoneId());
        List<AuditEvent> clientEvents = auditService.find("client", now - 2 * 60 * 1000, IdentityZone.getUaaZoneId());
        assertThat(userEvents).hasSize(1);
        assertThat(clientEvents).isEmpty();
    }

    @Test
    void nontAuthSuccessesShouldNotThrowAnException() {
        EnumSet<AuditEventType> userAuthenticationSuccess = EnumSet.of(UserAuthenticationSuccess, PasswordChangeSuccess, UserAccountUnlockedEvent);
        EnumSet<AuditEventType> complementOfUserAuthenticationSuccess = EnumSet.complementOf(userAuthenticationSuccess);

        for (AuditEventType ofUserAuthenticationSuccess : complementOfUserAuthenticationSuccess) {
            AuditEvent auditEvent = new AuditEvent(ofUserAuthenticationSuccess, "1", authDetails, "joe", System.currentTimeMillis(), IdentityZone.getUaaZoneId(), null, null);
            auditService.log(auditEvent, "some zone");
        }
    }

    @Test
    void userUnlockShouldResetUserAuthentication() {
        AuditEvent loginFailureEvent = new AuditEvent(UserAuthenticationFailure, "1", authDetails, "joe", System.currentTimeMillis(), IdentityZone.getUaaZoneId(), null, null);
        auditService.log(loginFailureEvent, loginFailureEvent.getIdentityZoneId());

        AuditEvent unlockEvent = new AuditEvent(UserAccountUnlockedEvent, "1", authDetails, "joe", System.currentTimeMillis(), IdentityZone.getUaaZoneId(), null, null);
        auditService.log(unlockEvent, unlockEvent.getIdentityZoneId());

        assertThat(auditService.find("1", 0, loginFailureEvent.getIdentityZoneId())).isEmpty();
    }

    private AuditEvent getAuditEvent(AuditEventType type, String principal, String data) {
        return new AuditEvent(type, principal, authDetails, data, System.currentTimeMillis(), IdentityZone.getUaaZoneId(), null, null);
    }
}
