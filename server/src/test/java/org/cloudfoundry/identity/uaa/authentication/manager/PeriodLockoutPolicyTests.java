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

import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.audit.UaaAuditService;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.LockoutPolicy;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.cloudfoundry.identity.uaa.util.TimeServiceImpl;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.core.Authentication;

import java.util.Arrays;

import static org.cloudfoundry.identity.uaa.audit.AuditEventType.MfaAuthenticationFailure;
import static org.cloudfoundry.identity.uaa.audit.AuditEventType.UserAuthenticationFailure;
import static org.cloudfoundry.identity.uaa.audit.AuditEventType.UserAuthenticationSuccess;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * @author Luke Taylor
 */
public class PeriodLockoutPolicyTests {
    private static final int ONE_HOUR = 60 * 60;

    private UaaAuditService as;
    private UaaUser joe;
    private long now;
    private PeriodLockoutPolicy policy;
    private CommonLoginPolicy innerPolicy;
    private CommonLoginPolicy mfaInnerPolicy;
    private LockoutPolicyRetriever policyRetriever;
    private LockoutPolicyRetriever mfaPolicyRetriever;
    private IdentityProviderProvisioning providerProvisioning;

    @Before
    public void setUp() {
        now = System.currentTimeMillis();
        as = mock(UaaAuditService.class);
        joe = mock(UaaUser.class);
        TimeService timeService = new TimeServiceImpl();
        when(joe.getId()).thenReturn("1");
        providerProvisioning = mock(IdentityProviderProvisioning.class);
        LockoutPolicy lockoutPolicy = new LockoutPolicy();
        lockoutPolicy.setCountFailuresWithin(ONE_HOUR);
        lockoutPolicy.setLockoutPeriodSeconds(ONE_HOUR);
        when(providerProvisioning.retrieveByOrigin(anyString(), anyString())).thenReturn(new IdentityProvider());
        policyRetriever = new UserLockoutPolicyRetriever(providerProvisioning);
        mfaPolicyRetriever = new UserLockoutPolicyRetriever(providerProvisioning);

        innerPolicy = new CommonLoginPolicy(as, policyRetriever, AuditEventType.UserAuthenticationSuccess, AuditEventType.UserAuthenticationFailure, timeService, true);
        mfaInnerPolicy = new CommonLoginPolicy(as, policyRetriever, AuditEventType.MfaAuthenticationSuccess, AuditEventType.MfaAuthenticationFailure, timeService, true);

        policyRetriever.setDefaultLockoutPolicy(lockoutPolicy);
        mfaPolicyRetriever.setDefaultLockoutPolicy(lockoutPolicy);
        policy = new PeriodLockoutPolicy(innerPolicy, mfaInnerPolicy);
    }

    @Test
    public void loginIsDeniedIfAllowedFailuresIsExceeded() {
        String zoneId = IdentityZoneHolder.get().getId();
        when(as.find(eq("1"), anyLong(), eq(zoneId))).thenReturn(Arrays.asList(
                        new AuditEvent(UserAuthenticationFailure, "joe", "", "", now - 1, IdentityZone.getUaaZoneId(), null, null),
                        new AuditEvent(UserAuthenticationFailure, "joe", "", "", now - 2, IdentityZone.getUaaZoneId(), null, null)
                        ));

        policyRetriever.getDefaultLockoutPolicy().setLockoutAfterFailures(2);
        assertFalse(policy.isAllowed(joe, mock(Authentication.class)));
    }

    @Test
    public void loginIsDeniedIfAllowedMFAFailuresIsExceeded() {
        String zoneId = IdentityZoneHolder.get().getId();
        when(as.find(eq("1"), anyLong(), eq(zoneId))).thenReturn(Arrays.asList(
          new AuditEvent(MfaAuthenticationFailure, "joe", "", "", now - 1, IdentityZone.getUaaZoneId(), null, null),
          new AuditEvent(MfaAuthenticationFailure, "joe", "", "", now - 2, IdentityZone.getUaaZoneId(), null, null)
        ));

        mfaPolicyRetriever.getDefaultLockoutPolicy().setLockoutAfterFailures(2);
        assertThat(policy.isAllowed(joe, mock(Authentication.class)), is(false));
    }

    @Test
    public void loginIsAllowedIfSuccessfulLoginIntercedesExcessiveFailures() {
        String zoneId = IdentityZoneHolder.get().getId();
        when(as.find(eq("1"), anyLong(), eq(zoneId))).thenReturn(Arrays.asList(
                        new AuditEvent(UserAuthenticationFailure, "joe", "", "", now - 1, IdentityZone.getUaaZoneId(), null, null),
                        new AuditEvent(UserAuthenticationSuccess, "joe", "", "", now - 2, IdentityZone.getUaaZoneId(), null, null),
                        new AuditEvent(UserAuthenticationFailure, "joe", "", "", now - 3, IdentityZone.getUaaZoneId(), null, null)
                        ));

        policy.getDefaultLockoutPolicy().setLockoutAfterFailures(2);
        assertTrue(policy.isAllowed(joe, mock(Authentication.class)));
    }

    @Test
    public void loginIsAllowedWithExcessiveFailuresIfLockoutPeriodHasElapsed() {
        String zoneId = IdentityZoneHolder.get().getId();
        when(as.find(eq("1"), anyLong(), eq(zoneId))).thenReturn(Arrays.asList(
                        new AuditEvent(UserAuthenticationFailure, "joe", "", "", now - 5001, IdentityZone.getUaaZoneId(), null, null),
                        new AuditEvent(UserAuthenticationSuccess, "joe", "", "", now - 5002, IdentityZone.getUaaZoneId(), null, null),
                        new AuditEvent(UserAuthenticationFailure, "joe", "", "", now - 5003, IdentityZone.getUaaZoneId(), null, null)
                        ));

        policy.getDefaultLockoutPolicy().setLockoutAfterFailures(2);
        policy.getDefaultLockoutPolicy().setLockoutPeriodSeconds(5);
        // Last failed login is before lockout period
        assertTrue(policy.isAllowed(joe, mock(Authentication.class)));
    }

    @Test
    public void loginIsAllowedIfAllowedFailuresIsNotExceeded() {
        String zoneId = IdentityZoneHolder.get().getId();
        when(as.find(eq("1"), anyLong(), eq(zoneId))).thenReturn(Arrays.asList(
                        new AuditEvent(UserAuthenticationFailure, "joe", "", "", now - 1, IdentityZone.getUaaZoneId(), null, null),
                        new AuditEvent(UserAuthenticationFailure, "joe", "", "", now - 2, IdentityZone.getUaaZoneId(), null, null)
                        ));

        policy.getDefaultLockoutPolicy().setLockoutAfterFailures(3);
        assertTrue(policy.isAllowed(joe, mock(Authentication.class)));
    }

    @Test
    public void testUseLockoutPolicyFromDbIfPresent() {
        String zoneId = IdentityZoneHolder.get().getId();
        when(as.find(eq("1"), anyLong(), eq(zoneId))).thenReturn(Arrays.asList(
            new AuditEvent(UserAuthenticationFailure, "joe", "", "", now - 1, IdentityZone.getUaaZoneId(), null, null),
            new AuditEvent(UserAuthenticationFailure, "joe", "", "", now - 1, IdentityZone.getUaaZoneId(), null, null)
        ));
        LockoutPolicy lockoutPolicy = new LockoutPolicy();
        lockoutPolicy.setLockoutAfterFailures(2);
        lockoutPolicy.setLockoutPeriodSeconds(900);
        lockoutPolicy.setCountFailuresWithin(3600);
        IdentityProvider<UaaIdentityProviderDefinition> provider = new IdentityProvider<>();
        provider.setConfig(new UaaIdentityProviderDefinition(null, lockoutPolicy));
        when(providerProvisioning.retrieveByOrigin(OriginKeys.UAA, zoneId)).thenReturn(provider);
        assertFalse(policy.isAllowed(joe, mock(Authentication.class)));
    }
}
