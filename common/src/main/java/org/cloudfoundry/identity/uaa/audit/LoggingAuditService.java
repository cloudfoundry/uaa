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
package org.cloudfoundry.identity.uaa.audit;

import java.security.Principal;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.springframework.jmx.export.annotation.ManagedMetric;
import org.springframework.jmx.export.annotation.ManagedResource;
import org.springframework.jmx.support.MetricType;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

/**
 * Audit service implementation which just outputs the relevant information through the logger.
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
	public void passwordChangeSuccess(String message, UaaUser user, Principal caller) {
		passwordChanges.incrementAndGet();
		log("Password change ('" + message + "'): user=" + user.getUsername() + "; " + extractCaller(caller));
	}

	@Override
	public void passwordChangeFailure(String message, UaaUser user, Principal caller) {
		passwordFailures.incrementAndGet();
		log("Password change failed ('" + message + "'): user=" + user.getUsername() + "; " + extractCaller(caller));
	}

	@Override
	public void passwordChangeFailure(String message, Principal caller) {
		passwordFailures.incrementAndGet();
		log("Password change failed with no user ('" + message + "'): " + extractCaller(caller));
	}

	@Override
	public void secretChangeSuccess(String message, ClientDetails client, Principal caller) {
		passwordChanges.incrementAndGet();
		log("Secret change ('" + message + "'): client=" + client.getClientId()+ "; " + extractCaller(caller));
	}

	@Override
	public void secretChangeFailure(String message, ClientDetails client, Principal caller) {
		passwordFailures.incrementAndGet();
		log("Secret change failed ('" + message + "'): client=" + client.getClientId() + "; " + extractCaller(caller));
	}

	@Override
	public void secretChangeFailure(String message, Principal caller) {
		passwordFailures.incrementAndGet();
		log("Secret change failed with no user ('" + message + "'): " + extractCaller(caller));
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

	private String extractCaller(Principal caller) {
		if (caller instanceof OAuth2Authentication) {
			OAuth2Authentication oAuth2Authentication = (OAuth2Authentication) caller;
			return "client=" + oAuth2Authentication.getAuthorizationRequest().getClientId()
					+ (oAuth2Authentication.isClientOnly() ? "" : "; user=" + caller.getName());
		}
		return caller == null ? null : caller.getName();
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
