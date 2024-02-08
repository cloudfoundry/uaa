package org.cloudfoundry.identity.uaa.audit;

import org.cloudfoundry.identity.uaa.util.TimeService;
import org.cloudfoundry.identity.uaa.util.TimeServiceImpl;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

import java.sql.Timestamp;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicLong;

import static org.cloudfoundry.identity.uaa.audit.AuditEventType.UserAuthenticationFailure;

/**
 * An audit service that subscribes to audit events but only saves enough data
 * to answer queries about consecutive
 * failed logins.
 */
@Component("jdbcAuditService")
public class JdbcUnsuccessfulLoginCountingAuditService extends JdbcAuditService {

    private final TimeService timeService;

    private final Duration saveDataPeriod;
    private final Duration timeBetweenDelete;

    private AtomicLong lastDelete;

    public JdbcUnsuccessfulLoginCountingAuditService(
            final JdbcTemplate template,
            final TimeService timeService) {
        super(template);
        this.timeService = timeService;
        this.lastDelete = new AtomicLong(0);
        this.saveDataPeriod = Duration.ofDays(1L);
        this.timeBetweenDelete = Duration.ofSeconds(30L);
    }

    @Override
    public void log(AuditEvent auditEvent, String zoneId) {
        switch (auditEvent.getType()) {
            case UserAuthenticationSuccess, PasswordChangeSuccess, UserAccountUnlockedEvent:
                resetAuthenticationEvents(auditEvent, zoneId, UserAuthenticationFailure);
                break;
            case UserAuthenticationFailure:
                periodicDelete();
                super.log(auditEvent, zoneId);
                break;
            default:
                break;
        }
    }

    private void resetAuthenticationEvents(AuditEvent auditEvent, String zoneId, AuditEventType eventType) {
        getJdbcTemplate().update("delete from sec_audit where principal_id=? and identity_zone_id=? and event_type=?", auditEvent.getPrincipalId(), zoneId, eventType.getCode());
    }

    protected void periodicDelete() {
        long now = timeService.getCurrentTimeMillis();
        long lastCheck = lastDelete.get();
        if (now - lastCheck > timeBetweenDelete.toMillis() && lastDelete.compareAndSet(lastCheck, now)) {
            getJdbcTemplate().update("delete from sec_audit where created < ?",
                    new Timestamp(System.currentTimeMillis()
                            - saveDataPeriod.toMillis()));
        }
    }

}
