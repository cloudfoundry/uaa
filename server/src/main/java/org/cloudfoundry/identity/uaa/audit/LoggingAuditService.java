/*******************************************************************************
 *     Cloud Foundry 
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.audit;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jmx.export.annotation.ManagedMetric;
import org.springframework.jmx.export.annotation.ManagedResource;
import org.springframework.jmx.support.MetricType;

/**
 * Audit service implementation which just outputs the relevant information
 * through the logger.
 * <p>
 * Also accumulates count data for exposure through /varz
 * 
 * @author Luke Taylor
 * @author Dave Syer
 */
@ManagedResource
public class LoggingAuditService implements UaaAuditService {

    private final Log logger = LogFactory.getLog("UAA.Audit");

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
    public List<AuditEvent> find(String principal, long after) {
        throw new UnsupportedOperationException("This implementation does not store data");
    }

    @Override
    public void log(AuditEvent auditEvent) {
        updateCounters(auditEvent);
        log(String.format("%s ('%s'): principal=%s, origin=[%s], identityZoneId=[%s]", auditEvent.getType().name(), auditEvent.getData(),
                        auditEvent.getPrincipalId(), auditEvent.getOrigin(), auditEvent.getIdentityZoneId()));
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
        if (logger.isTraceEnabled()) {
            StringBuilder output = new StringBuilder(256);
            output.append("\n************************************************************\n");
            output.append(msg);
            output.append("\n\n************************************************************\n");
            logger.trace(output.toString());
        }
        else {
            logger.info(msg);
        }
    }
}
