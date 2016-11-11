/*******************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 * <p>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.authentication.manager;

import java.util.List;

import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.audit.UaaAuditService;
import org.cloudfoundry.identity.uaa.provider.LockoutPolicy;


/**
 * Common login policy for both user login and client credential authentication, specifically for
 * lockouts.
 */
public class CommonLoginPolicy implements LoginPolicy {
    private final UaaAuditService auditService;
    private final LockoutPolicyRetriever lockoutPolicyRetriever;
    private final AuditEventType successEventType;
    private final AuditEventType failureEventType;
    
    public CommonLoginPolicy(UaaAuditService auditService, LockoutPolicyRetriever lockoutPolicyRetriever, AuditEventType successEventType,
            AuditEventType failureEventType) {
        this.auditService = auditService;
        this.lockoutPolicyRetriever = lockoutPolicyRetriever;
        this.successEventType = successEventType;
        this.failureEventType = failureEventType;
    }

    @Override
    public Result isAllowed(String principalId) {
        LockoutPolicy lockoutPolicy = lockoutPolicyRetriever.getLockoutPolicy();
        
        long eventsAfter = System.currentTimeMillis() - lockoutPolicy.getCountFailuresWithin() * 1000;
        List<AuditEvent> events = auditService.find(principalId, eventsAfter);

        final int failureCount = sequentialFailureCount(events);

        if (failureCount >= lockoutPolicy.getLockoutAfterFailures()) {
            // Check whether time of most recent failure is within the lockout
            // period
            AuditEvent lastFailure = mostRecentFailure(events);
            if (lastFailure != null && lastFailure.getTime() > System.currentTimeMillis() - lockoutPolicy.getLockoutPeriodSeconds() * 1000) {
                return new Result(false, failureCount);
            }
        }
        return new Result(true, failureCount);
    }
    
    /**
     * Counts the number of failures that occurred without an intervening
     * successful login.
     */
    private int sequentialFailureCount(List<AuditEvent> events) {
        int failureCount = 0;
        for (AuditEvent event : events) {
            if (event.getType() == failureEventType) {
                failureCount++;
            } else if (event.getType() == successEventType) {
                // Successful authentication occurred within last allowable
                // failures, so ignore
                break;
            }
        }
        return failureCount;
    }
    
    private AuditEvent mostRecentFailure(List<AuditEvent> events) {
        for (AuditEvent event : events) {
            if (event.getType() == failureEventType) {
                return event;
            }
        }
        return null;
    }
    
    public LockoutPolicyRetriever getLockoutPolicyRetriever() {
        return lockoutPolicyRetriever;
    }
}
