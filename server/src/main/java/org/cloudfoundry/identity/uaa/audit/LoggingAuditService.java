package org.cloudfoundry.identity.uaa.audit;

import org.cloudfoundry.identity.uaa.logging.LogSanitizerUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jmx.export.annotation.ManagedMetric;
import org.springframework.jmx.export.annotation.ManagedResource;
import org.springframework.jmx.support.MetricType;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Audit service implementation which just outputs the relevant information
 * through the logger.
 *
 * Keep this as a top-level bean to ensure it is exposed as a @ManagedResource
 *
 * @author Luke Taylor
 * @author Dave Syer
 */
@ManagedResource
        (
        objectName = "cloudfoundry.identity:name=UaaAudit",
        description = "UAA Audit Metrics"
)
@Component("loggingAuditService")
public class LoggingAuditService implements UaaAuditService {

    private Logger logger = LoggerFactory.getLogger("UAA.Audit");

    private AtomicInteger userAuthenticationCount = new AtomicInteger();

    private AtomicInteger userAuthenticationFailureCount = new AtomicInteger();

    private AtomicInteger clientAuthenticationCount = new AtomicInteger();

    private AtomicInteger clientAuthenticationFailureCount = new AtomicInteger();

    private AtomicInteger principalAuthenticationFailureCount = new AtomicInteger();

    private AtomicInteger userNotFoundCount = new AtomicInteger();

    private AtomicInteger principalNotFoundCount = new AtomicInteger();

    private AtomicInteger passwordChanges = new AtomicInteger();

    private AtomicInteger passwordFailures = new AtomicInteger();

    @ManagedMetric(metricType = MetricType.COUNTER, displayName = "User Not Found Count")
    public int getUserNotFoundCount() {
        return userNotFoundCount.get();
    }

    @ManagedMetric(metricType = MetricType.COUNTER, displayName = "User Successful Authentication Count")
    public int getUserAuthenticationCount() {
        return userAuthenticationCount.get();
    }

    @ManagedMetric(metricType = MetricType.COUNTER, displayName = "User Authentication Failure Count")
    public int getUserAuthenticationFailureCount() {
        return userAuthenticationFailureCount.get();
    }

    @ManagedMetric(metricType = MetricType.COUNTER, displayName = "Client Successful Authentication Count")
    public int getClientAuthenticationCount() {
        return clientAuthenticationCount.get();
    }

    @ManagedMetric(metricType = MetricType.COUNTER, displayName = "Client Authentication Failure Count")
    public int getClientAuthenticationFailureCount() {
        return clientAuthenticationFailureCount.get();
    }

    @ManagedMetric(metricType = MetricType.COUNTER, displayName = "Principal (non-user) Authentication Failure Count")
    public int getPrincipalAuthenticationFailureCount() {
        return principalAuthenticationFailureCount.get();
    }

    @ManagedMetric(metricType = MetricType.COUNTER, displayName = "Principal (non-user) Not Found Count")
    public int getPrincipalNotFoundCount() {
        return principalNotFoundCount.get();
    }

    @ManagedMetric(metricType = MetricType.COUNTER, displayName = "User Password Change Count (Since Startup)")
    public int getUserPasswordChanges() {
        return passwordChanges.get();
    }

    @ManagedMetric(metricType = MetricType.COUNTER, displayName = "User Password Change Failure Count (Since Startup)")
    public int getUserPasswordFailures() {
        return passwordFailures.get();
    }

    @Override
    public List<AuditEvent> find(String principal, long after, String zoneId) {
        throw new UnsupportedOperationException("This implementation does not store data");
    }

    @Override
    public void log(AuditEvent auditEvent, String zoneId) {
        updateCounters(auditEvent);

        String logMessage = "%s ('%s'): principal=%s, origin=[%s], identityZoneId=[%s]".formatted(
                auditEvent.getType().name(),
                auditEvent.getData(),
                auditEvent.getPrincipalId(),
                auditEvent.getOrigin(),
                auditEvent.getIdentityZoneId()
        );

        if (auditEvent.getAuthenticationType() != null) {
            logMessage = "%s, authenticationType=[%s]".formatted(logMessage, auditEvent.getAuthenticationType());
        }

        if (auditEvent.getDescription() != null) {
            logMessage = "%s, detailedDescription=[%s]".formatted(logMessage, auditEvent.getDescription());
        }

        log(logMessage);
    }

    private void updateCounters(AuditEvent auditEvent) {
        switch (auditEvent.getType()) {
            case PasswordChangeSuccess:
                passwordChanges.incrementAndGet();
                break;
            case PasswordChangeFailure:
                passwordFailures.incrementAndGet();
                break;
            case UserAuthenticationSuccess:
                userAuthenticationCount.incrementAndGet();
                break;
            case UserAuthenticationFailure:
                userAuthenticationFailureCount.incrementAndGet();
                break;
            case ClientAuthenticationSuccess:
                clientAuthenticationCount.incrementAndGet();
                break;
            case ClientAuthenticationFailure:
                clientAuthenticationFailureCount.incrementAndGet();
                break;
            case UserNotFound:
                userNotFoundCount.incrementAndGet();
                break;
            case PrincipalAuthenticationFailure:
                principalAuthenticationFailureCount.incrementAndGet();
                break;
            case PrincipalNotFound:
                principalNotFoundCount.incrementAndGet();
                break;
            default:
                break;
        }
    }

    private void log(String msg) {
        String sanitized = LogSanitizerUtil.sanitize(msg);

        if (logger.isTraceEnabled()) {
            StringBuilder output = new StringBuilder(256);
            output.append("\n************************************************************\n");
            output.append(sanitized);
            output.append("\n\n************************************************************\n");
            logger.trace(output.toString());
        } else {
            logger.info(sanitized);
        }
    }

    public void setLogger(Logger logger) {
        this.logger = logger;
    }

    public Logger getLogger() {
        return logger;
    }
}
