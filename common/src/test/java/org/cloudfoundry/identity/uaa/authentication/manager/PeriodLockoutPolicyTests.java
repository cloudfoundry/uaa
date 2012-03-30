/*
 * Cloud Foundry 2012.02.03 Beta
 * Copyright (c) [2009-2012] VMware, Inc. All Rights Reserved.
 *
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 *
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 */
package org.cloudfoundry.identity.uaa.authentication.manager;

import java.util.Arrays;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;
import static org.cloudfoundry.identity.uaa.audit.AuditEventType.*;

import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.UaaAuditService;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.core.Authentication;


/**
 * @author Luke Taylor
 */
public class PeriodLockoutPolicyTests {
	private static final int ONE_HOUR = 60*60;

	private UaaAuditService as;
	private UaaUser joe;
	private long now;
	private PeriodLockoutPolicy policy;

	@Before
	public void setUp() throws Exception {
		now = System.currentTimeMillis();
		as = mock(UaaAuditService.class);
		joe = mock(UaaUser.class);
		when(joe.getId()).thenReturn("1");
		policy = new PeriodLockoutPolicy(as);
		policy.setCountFailuresWithin(ONE_HOUR);
		policy.setLockoutPeriodSeconds(ONE_HOUR);
	}

	@Test
	public void loginIsDeniedIfAllowedFailuresIsExceeded() {
		when(as.find(eq("1"), anyLong())).thenReturn(Arrays.asList(
						new AuditEvent(UserAuthenticationFailure, "joe", "","", now - 1),
						new AuditEvent(UserAuthenticationFailure, "joe", "", "", now - 2)
				));

		policy.setLockoutAfterFailures(2);
		assertFalse(policy.isAllowed(joe, mock(Authentication.class)));
	}

	@Test
	public void loginIsAllowedIfSuccessfulLoginIntercedesExcessiveFailures() {
		when(as.find(eq("1"), anyLong())).thenReturn(Arrays.asList(
						new AuditEvent(UserAuthenticationFailure, "joe", "", "", now - 1),
						new AuditEvent(UserAuthenticationSuccess, "joe", "", "", now - 2),
						new AuditEvent(UserAuthenticationFailure, "joe", "", "", now - 3)
				));

		policy.setLockoutAfterFailures(2);
		assertTrue(policy.isAllowed(joe, mock(Authentication.class)));
	}

	@Test
	public void loginIsAllowedWithExcessiveFailuresIfLockoutPeriodHasElapsed() {
		when(as.find(eq("1"), anyLong())).thenReturn(Arrays.asList(
						new AuditEvent(UserAuthenticationFailure, "joe", "", "", now - 5001),
						new AuditEvent(UserAuthenticationSuccess, "joe", "", "", now - 5002),
						new AuditEvent(UserAuthenticationFailure, "joe", "", "", now - 5003)
				));

		policy.setLockoutAfterFailures(2);
		policy.setLockoutPeriodSeconds(5);
		// Last failed login is before lockout period
		assertTrue(policy.isAllowed(joe, mock(Authentication.class)));
	}


	@Test
	public void loginIsAllowedIfAllowedFailuresIsNotExceeded() {
		when(as.find(eq("1"), anyLong())).thenReturn(Arrays.asList(
						new AuditEvent(UserAuthenticationFailure, "joe", "", "", now - 1),
						new AuditEvent(UserAuthenticationFailure, "joe", "", "", now - 2)
				));

		policy.setLockoutAfterFailures(3);
		assertTrue(policy.isAllowed(joe, mock(Authentication.class)));
	}
}
