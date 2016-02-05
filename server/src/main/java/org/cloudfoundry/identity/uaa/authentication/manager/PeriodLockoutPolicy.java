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
package org.cloudfoundry.identity.uaa.authentication.manager;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.audit.UaaAuditService;
import org.cloudfoundry.identity.uaa.provider.LockoutPolicy;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.util.ObjectUtils;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import java.util.List;

/**
 * Locks an account out for a configured period based on the number of failed
 * logins since a specific time in the past.
 * <p>
 * Queries the audit service to obtain the relevant data for the user.
 *
 * @author Luke Taylor
 */
public class PeriodLockoutPolicy implements AccountLoginPolicy {

    private final Log logger = LogFactory.getLog(getClass());
    private final UaaAuditService auditService;
    private LockoutPolicy lockoutPolicy;
    private IdentityProviderProvisioning providerProvisioning;

    public PeriodLockoutPolicy(UaaAuditService auditService, IdentityProviderProvisioning providerProvisioning) {
        this.auditService = auditService;
        this.providerProvisioning = providerProvisioning;
    }

    @Override
    public boolean isAllowed(UaaUser user, Authentication a) throws AuthenticationException {
        LockoutPolicy policyFromDb = getLockoutPolicyFromDb();
        LockoutPolicy localPolicy = policyFromDb != null ? policyFromDb : lockoutPolicy;

        long eventsAfter = System.currentTimeMillis() - localPolicy.getCountFailuresWithin() * 1000;

        List<AuditEvent> events = auditService.find(user.getId(), eventsAfter);

        final int failureCount = sequentialFailureCount(events);

        if (failureCount >= localPolicy.getLockoutAfterFailures()) {
            // Check whether time of most recent failure is within the lockout
            // period
            AuditEvent lastFailure = mostRecentFailure(events);
            if (lastFailure != null && lastFailure.getTime() > System.currentTimeMillis() - localPolicy.getLockoutPeriodSeconds() * 1000) {
                logger.warn("User " + user.getUsername() + " and id " + user.getId() + " has "
                                + failureCount + " failed logins within the last checking period.");
                return false;
            }
        }

        return true;
    }

    /**
     * Counts the number of failures that occurred without an intervening
     * successful login.
     */
    private int sequentialFailureCount(List<AuditEvent> events) {
        int failureCount = 0;
        for (AuditEvent event : events) {
            if (event.getType() == AuditEventType.UserAuthenticationFailure) {
                failureCount++;
            } else if (event.getType() == AuditEventType.UserAuthenticationSuccess) {
                // Successful authentication occurred within last allowable
                // failures, so ignore
                break;
            }
        }
        return failureCount;
    }

    private AuditEvent mostRecentFailure(List<AuditEvent> events) {
        for (AuditEvent event : events) {
            if (event.getType() == AuditEventType.UserAuthenticationFailure) {
                return event;
            }
        }
        return null;
    }

    public void setLockoutPolicy(LockoutPolicy lockoutPolicy) {
        this.lockoutPolicy = lockoutPolicy;
    }

    private LockoutPolicy getLockoutPolicyFromDb() {
        IdentityProvider idp = providerProvisioning.retrieveByOrigin(OriginKeys.UAA, IdentityZoneHolder.get().getId());
        UaaIdentityProviderDefinition idpDefinition = ObjectUtils.castInstance(idp.getConfig(), UaaIdentityProviderDefinition.class);
        if (idpDefinition != null && idpDefinition.getLockoutPolicy() !=null ) {
            return idpDefinition.getLockoutPolicy();
        }
        return null;
    }

    public LockoutPolicy getLockoutPolicy() {
        return lockoutPolicy;
    }
}
