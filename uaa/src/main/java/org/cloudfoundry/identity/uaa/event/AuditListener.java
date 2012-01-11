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
package org.cloudfoundry.identity.uaa.event;

import org.cloudfoundry.identity.uaa.audit.LoggingAuditService;
import org.cloudfoundry.identity.uaa.audit.UaaAuditService;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
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
	private final UaaAuditService auditor;

	public AuditListener() {
		auditor = new LoggingAuditService();
	}

	public AuditListener(UaaAuditService auditor) {
		Assert.notNull(auditor);
		this.auditor = auditor;
	}

	@Override
	public void onApplicationEvent(ApplicationEvent event) {
		if (event instanceof AbstractUaaEvent) {
			((AbstractUaaEvent)event).process(auditor);
		} else if (event instanceof AuthenticationFailureBadCredentialsEvent) {
			AuthenticationFailureBadCredentialsEvent bce = (AuthenticationFailureBadCredentialsEvent)event;
			String principal = bce.getAuthentication().getName();
			UaaAuthenticationDetails details = (UaaAuthenticationDetails) bce.getAuthentication().getDetails();

			if (bce.getException() instanceof UsernameNotFoundException) {
				auditor.principalNotFound(principal, details);
			} else {
				auditor.principalAuthenticationFailure(principal, details);
			}
		}
	}
}
