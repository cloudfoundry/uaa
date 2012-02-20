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
package org.cloudfoundry.identity.uaa.audit;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.springframework.jmx.export.annotation.ManagedMetric;
import org.springframework.jmx.export.annotation.ManagedResource;
import org.springframework.jmx.support.MetricType;

/**
 * Audit service implementation which just outputs the relevant
 * information through the logger.
 * <p>
 * Also accumulates count data for exposure through /varz
 *
 * @author Luke Taylor
 * @author Dave Syer
 */
@ManagedResource
public class LoggingAuditService implements UaaAuditService {
	private final Log logger = LogFactory.getLog("UAA Audit Logger");
	private AtomicInteger userAuthenticationCount = new AtomicInteger();
	private AtomicInteger userAuthenticationFailureCount = new AtomicInteger();
	private AtomicInteger principalAuthenticationFailureCount = new AtomicInteger();
	private AtomicInteger userNotFoundCount = new AtomicInteger();
	private AtomicInteger principalNotFoundCount = new AtomicInteger();

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

	@ManagedMetric(metricType = MetricType.COUNTER, displayName = "Principal (non-user) Authentication Failure Count")
	public int getPrincipalAuthenticationFailureCount() {
		return principalAuthenticationFailureCount.get();
	}

	@ManagedMetric(metricType = MetricType.COUNTER, displayName = "Principal (non-user) Not Found Count")
	public int getPrincipalNotFoundCount() {
		return principalNotFoundCount.get();
	}

	@Override
	public void userAuthenticationSuccess(UaaUser user, UaaAuthenticationDetails details) {
		userAuthenticationCount.incrementAndGet();
		log("User authenticated: " + user.getId() + ", " + user.getUsername());
	}

	@Override
	public void userAuthenticationFailure(UaaUser user, UaaAuthenticationDetails details) {
		userAuthenticationFailureCount.incrementAndGet();
		log("Authentication failed, user: " + user.getId() + ", " + user.getUsername());
	}

	@Override
	public void userNotFound(String name, UaaAuthenticationDetails details) {
		userNotFoundCount.incrementAndGet();
		log("Attempt to login as non-existent user: " + name);
	}

	@Override
	public void principalAuthenticationFailure(String name, UaaAuthenticationDetails details) {
		principalAuthenticationFailureCount.incrementAndGet();
		log("Authentication failed, principal: " + name);
	}

	@Override
	public void principalNotFound(String name, UaaAuthenticationDetails details) {
		principalNotFoundCount.incrementAndGet();
		log("Authentication failed, principal not found: " + name);
	}

	@Override
	public List<AuditEvent> find(String principal, long after) {
		throw new UnsupportedOperationException("This implementation does not store data");
	}

	private void log(String msg) {
		StringBuilder output = new StringBuilder(256);
  		output.append("\n\n************************************************************\n\n");
		output.append(msg).append("\n");
		output.append("\n\n************************************************************\n\n");
		logger.trace(output.toString());
	}
}
