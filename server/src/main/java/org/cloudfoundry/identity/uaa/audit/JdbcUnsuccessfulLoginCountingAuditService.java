package org.cloudfoundry.identity.uaa.audit;

import static org.cloudfoundry.identity.uaa.audit.AuditEventType.MfaAuthenticationFailure;
import static org.cloudfoundry.identity.uaa.audit.AuditEventType.UserAuthenticationFailure;

import java.sql.Timestamp;
import java.util.concurrent.atomic.AtomicLong;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.cloudfoundry.identity.uaa.util.TimeServiceImpl;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * An audit service that subscribes to audit events but only saves enough data to answer queries
 * about consecutive failed logins.
 */
public class JdbcUnsuccessfulLoginCountingAuditService extends JdbcAuditService {

  private int saveDataPeriodMillis = 24 * 3600 * 1000; // 24hr
  private long timeBetweenDeleteMillis = 1000 * 30;

  private AtomicLong lastDelete = new AtomicLong(0);
  private TimeService timeService = new TimeServiceImpl();

  public JdbcUnsuccessfulLoginCountingAuditService(JdbcTemplate template) {
    super(template);
  }

  /** @param saveDataPeriodMillis the period in milliseconds to set */
  public void setSaveDataPeriodMillis(int saveDataPeriodMillis) {
    this.saveDataPeriodMillis = saveDataPeriodMillis;
  }

  public void setTimeService(TimeService timeService) {
    this.timeService = timeService;
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

  private void resetAuthenticationEvents(
      AuditEvent auditEvent, String zoneId, AuditEventType eventType) {
    getJdbcTemplate()
        .update(
            "delete from sec_audit where principal_id=? and identity_zone_id=? and event_type=?",
            auditEvent.getPrincipalId(),
            zoneId,
            eventType.getCode());
  }

  protected void periodicDelete() {
    long now = timeService.getCurrentTimeMillis();
    long lastCheck = lastDelete.get();
    if (now - lastCheck > timeBetweenDeleteMillis && lastDelete.compareAndSet(lastCheck, now)) {
      getJdbcTemplate()
          .update(
              "delete from sec_audit where created < ?",
              new Timestamp(System.currentTimeMillis() - saveDataPeriodMillis));
    }
  }
}
