/*
 * Copyright 2006-2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.cloudfoundry.identity.uaa.authentication.manager;

import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.audit.UaaAuditService;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

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
	private int lockoutPeriodMs = 300000;  // 5 mins
	private int lockoutAfterFailures = 5;
	private int countFailuresWithinMs = 3600*1000; // 1hr

	public PeriodLockoutPolicy(UaaAuditService auditService) {
		this.auditService = auditService;
	}

	@Override
	public boolean isAllowed(UaaUser user, Authentication a) throws AuthenticationException {
		long eventsAfter = System.currentTimeMillis() - countFailuresWithinMs;

		List<AuditEvent> events = auditService.find(user.getId(), eventsAfter);

		final int failureCount = sequentialFailureCount(events);

		if (failureCount >= lockoutAfterFailures) {
			// Check whether time of most recent failure is within the lockout period
			AuditEvent lastFailure = mostRecentFailure(events);
			if (lastFailure != null && lastFailure.getTime() > System.currentTimeMillis() - lockoutPeriodMs) {
				logger.warn("User " + user.getId() + " has "
					+ failureCount + " failed logins within the last checking period." );
				return false;
			}
		}

		return true;
	}

	/**
	 * Counts the number of failures that occurred without an intervening successful login.
	 */
	private int sequentialFailureCount(List<AuditEvent> events) {
		int failureCount = 0;
		for (AuditEvent event: events) {
			if (event.getType() == AuditEventType.UserAuthenticationFailure) {
				failureCount++;
			} else if (event.getType() == AuditEventType.UserAuthenticationSuccess) {
				// Successful authentication occurred within last allowable failures, so ignore
				break;
			}
		}
		return failureCount;
	}

	public void setLockoutPeriodSeconds(int lockoutPeriod) {
		this.lockoutPeriodMs = lockoutPeriod * 1000;
	}

	public void setLockoutAfterFailures(int allowedFailures) {
		this.lockoutAfterFailures = allowedFailures;
	}

	/**
	 * Only audit events within the preceding interval will be considered
	 *
	 * @param interval the history period to consider (in seconds)
	 */
	public void setCountFailuresWithin(int interval) {
		this.countFailuresWithinMs = interval*1000;
	}

	private AuditEvent mostRecentFailure(List<AuditEvent> events) {
		for (AuditEvent event: events) {
			if (event.getType() == AuditEventType.UserAuthenticationFailure) {
				return event;
			}
		}
		return null;
	}


}
