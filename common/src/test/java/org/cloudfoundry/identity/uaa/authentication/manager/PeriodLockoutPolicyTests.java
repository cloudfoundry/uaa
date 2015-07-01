/*******************************************************************************
 *     Cloud Foundry 
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
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

import static org.cloudfoundry.identity.uaa.audit.AuditEventType.UserAuthenticationFailure;
import static org.cloudfoundry.identity.uaa.audit.AuditEventType.UserAuthenticationSuccess;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.anyLong;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Arrays;

import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.UaaAuditService;
import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.config.LockoutPolicy;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityProvider;
import org.cloudfoundry.identity.uaa.zone.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.UaaIdentityProviderDefinition;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.core.Authentication;

/**
 * @author Luke Taylor
 */
public class PeriodLockoutPolicyTests {
    private static final int ONE_HOUR = 60 * 60;

    private UaaAuditService as;
    private UaaUser joe;
    private long now;
    private PeriodLockoutPolicy policy;
    private IdentityProviderProvisioning providerProvisioning;

    @Before
    public void setUp() throws Exception {
        now = System.currentTimeMillis();
        as = mock(UaaAuditService.class);
        joe = mock(UaaUser.class);
        when(joe.getId()).thenReturn("1");
        providerProvisioning = mock(IdentityProviderProvisioning.class);
        LockoutPolicy lockoutPolicy = new LockoutPolicy();
        lockoutPolicy.setCountFailuresWithin(ONE_HOUR);
        lockoutPolicy.setLockoutPeriodSeconds(ONE_HOUR);
        when(providerProvisioning.retrieveByOrigin(anyString(), anyString())).thenReturn(new IdentityProvider());
        policy = new PeriodLockoutPolicy(as, providerProvisioning);
        policy.setLockoutPolicy(lockoutPolicy);
    }

    @Test
    public void loginIsDeniedIfAllowedFailuresIsExceeded() {
        when(as.find(eq("1"), anyLong())).thenReturn(Arrays.asList(
                        new AuditEvent(UserAuthenticationFailure, "joe", "", "", now - 1, IdentityZone.getUaa().getId()),
                        new AuditEvent(UserAuthenticationFailure, "joe", "", "", now - 2, IdentityZone.getUaa().getId())
                        ));

        policy.getLockoutPolicy().setLockoutAfterFailures(2);
        assertFalse(policy.isAllowed(joe, mock(Authentication.class)));
    }

    @Test
    public void loginIsAllowedIfSuccessfulLoginIntercedesExcessiveFailures() {
        when(as.find(eq("1"), anyLong())).thenReturn(Arrays.asList(
                        new AuditEvent(UserAuthenticationFailure, "joe", "", "", now - 1, IdentityZone.getUaa().getId()),
                        new AuditEvent(UserAuthenticationSuccess, "joe", "", "", now - 2, IdentityZone.getUaa().getId()),
                        new AuditEvent(UserAuthenticationFailure, "joe", "", "", now - 3, IdentityZone.getUaa().getId())
                        ));

        policy.getLockoutPolicy().setLockoutAfterFailures(2);
        assertTrue(policy.isAllowed(joe, mock(Authentication.class)));
    }

    @Test
    public void loginIsAllowedWithExcessiveFailuresIfLockoutPeriodHasElapsed() {
        when(as.find(eq("1"), anyLong())).thenReturn(Arrays.asList(
                        new AuditEvent(UserAuthenticationFailure, "joe", "", "", now - 5001, IdentityZone.getUaa().getId()),
                        new AuditEvent(UserAuthenticationSuccess, "joe", "", "", now - 5002, IdentityZone.getUaa().getId()),
                        new AuditEvent(UserAuthenticationFailure, "joe", "", "", now - 5003, IdentityZone.getUaa().getId())
                        ));

        policy.getLockoutPolicy().setLockoutAfterFailures(2);
        policy.getLockoutPolicy().setLockoutPeriodSeconds(5);
        // Last failed login is before lockout period
        assertTrue(policy.isAllowed(joe, mock(Authentication.class)));
    }

    @Test
    public void loginIsAllowedIfAllowedFailuresIsNotExceeded() {
        when(as.find(eq("1"), anyLong())).thenReturn(Arrays.asList(
                        new AuditEvent(UserAuthenticationFailure, "joe", "", "", now - 1, IdentityZone.getUaa().getId()),
                        new AuditEvent(UserAuthenticationFailure, "joe", "", "", now - 2, IdentityZone.getUaa().getId())
                        ));

        policy.getLockoutPolicy().setLockoutAfterFailures(3);
        assertTrue(policy.isAllowed(joe, mock(Authentication.class)));
    }

    @Test
    public void testUseLockoutPolicyFromDbIfPresent() throws Exception {
        when(as.find(eq("1"), anyLong())).thenReturn(Arrays.asList(
            new AuditEvent(UserAuthenticationFailure, "joe", "", "", now - 1, IdentityZone.getUaa().getId()),
            new AuditEvent(UserAuthenticationFailure, "joe", "", "", now - 1, IdentityZone.getUaa().getId())
        ));

        LockoutPolicy lockoutPolicy = new LockoutPolicy();
        lockoutPolicy.setLockoutAfterFailures(2);
        lockoutPolicy.setLockoutPeriodSeconds(900);
        lockoutPolicy.setCountFailuresWithin(3600);
        IdentityProvider provider = new IdentityProvider();
        provider.setConfig(JsonUtils.writeValueAsString(new UaaIdentityProviderDefinition(null, lockoutPolicy)));
        when(providerProvisioning.retrieveByOrigin(Origin.UAA, IdentityZoneHolder.get().getId())).thenReturn(provider);

        assertFalse(policy.isAllowed(joe, mock(Authentication.class)));
    }
}
