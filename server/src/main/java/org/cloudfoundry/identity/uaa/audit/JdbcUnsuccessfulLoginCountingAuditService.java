package org.cloudfoundry.identity.uaa.audit;

import org.cloudfoundry.identity.uaa.util.TimeService;
import org.cloudfoundry.identity.uaa.util.TimeServiceImpl;
import org.springframework.jdbc.core.JdbcTemplate;

import java.sql.Timestamp;
import java.util.concurrent.atomic.AtomicLong;

import static org.cloudfoundry.identity.uaa.audit.AuditEventType.MfaAuthenticationFailure;
import static org.cloudfoundry.identity.uaa.audit.AuditEventType.UserAuthenticationFailure;

/**
 * An audit service that subscribes to audit events but only saves enough data
 * to answer queries about consecutive
 * failed logins.
 */
public class JdbcUnsuccessfulLoginCountingAuditService extends JdbcAuditService {

    private final TimeService timeService;

    private final int saveDataPeriodMillis;
    private final long timeBetweenDeleteMillis;

    private AtomicLong lastDelete;

    public JdbcUnsuccessfulLoginCountingAuditService(
            final JdbcTemplate template,
            final TimeService timeService) {
        super(template);
        this.timeService = timeService;
        this.lastDelete = new AtomicLong(0);
        this.saveDataPeriodMillis = 24 * 3600 * 1000;  // 24hr
        this.timeBetweenDeleteMillis = 1000 * 30;
    }

    @Override
    public void log(AuditEvent auditEvent, String zoneId) {
        switch (auditEvent.getType()) {
            case MfaAuthenticationSuccess:
                resetAuthenticationEvents(auditEvent, zoneId, MfaAuthenticationFailure);

                break;
            case UserAuthenticationSuccess:
            case PasswordChangeSuccess:
                resetAuthenticationEvents(auditEvent, zoneId, UserAuthenticationFailure);
                break;
            case UserAccountUnlockedEvent:
                resetAuthenticationEvents(auditEvent, zoneId, UserAuthenticationFailure);
                resetAuthenticationEvents(auditEvent, zoneId, MfaAuthenticationFailure);
                break;
            case UserAuthenticationFailure:
            case MfaAuthenticationFailure:
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
        if (now - lastCheck > timeBetweenDeleteMillis && lastDelete.compareAndSet(lastCheck, now)) {
            getJdbcTemplate().update("delete from sec_audit where created < ?",
                    new Timestamp(System.currentTimeMillis()
                            - saveDataPeriodMillis));
        }
    }

}
