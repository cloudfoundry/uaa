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
package org.cloudfoundry.identity.uaa.event.listener;

import org.cloudfoundry.identity.uaa.audit.LoggingAuditService;
import org.cloudfoundry.identity.uaa.audit.UaaAuditService;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.event.AbstractUaaEvent;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.Assert;

/**
 * Spring {@code ApplicationListener} which picks up the listens for {@code AbstractUaaEvent}s and
 * passes the relevant information to the {@code UaaAuditService}.
 *
 * @author Luke Taylor
 */
public class AuditListener implements ApplicationListener<ApplicationEvent> {
	private final UaaAuditService uaaAuditService;

	public AuditListener() {
		uaaAuditService = new LoggingAuditService();
	}

	public AuditListener(UaaAuditService auditor) {
		Assert.notNull(auditor);
		this.uaaAuditService = auditor;
	}
	
	@Override
	public void onApplicationEvent(ApplicationEvent event) {
		if (event instanceof AbstractUaaEvent) {
			((AbstractUaaEvent)event).process(uaaAuditService);
		} else if (event instanceof AuthenticationFailureBadCredentialsEvent) {
			AuthenticationFailureBadCredentialsEvent bce = (AuthenticationFailureBadCredentialsEvent)event;
			String principal = bce.getAuthentication().getName();
			UaaAuthenticationDetails details = (UaaAuthenticationDetails) bce.getAuthentication().getDetails();

			if (bce.getException() instanceof UsernameNotFoundException) {
				uaaAuditService.principalNotFound(principal, details);
			} else {
				uaaAuditService.principalAuthenticationFailure(principal, details);
			}
		}
	}
}
