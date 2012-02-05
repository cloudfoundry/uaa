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
package org.cloudfoundry.identity.uaa.event.listener;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import javax.servlet.http.HttpServletRequest;

import org.cloudfoundry.identity.uaa.audit.UaaAuditService;
import org.cloudfoundry.identity.uaa.authentication.AuthzAuthenticationRequest;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.event.UserAuthenticationFailureEvent;
import org.cloudfoundry.identity.uaa.event.UserAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.event.UserNotFoundEvent;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.core.Authentication;

/**
 * @author Luke Taylor
 */
public class AuditListenerTests {
	private AuditListener listener;
	private UaaAuditService auditor;
	private UaaUser user = new UaaUser("auser", "password", "auser@blah.com", "A", "User");
	private UaaAuthenticationDetails details = new UaaAuthenticationDetails(mock(HttpServletRequest.class));

	@Before
	public void setUp() throws Exception {
		auditor = mock(UaaAuditService.class);
		listener = new AuditListener(auditor);
	}

	@Test
	public void userNotFoundIsAudited() throws Exception {
		AuthzAuthenticationRequest req = new AuthzAuthenticationRequest("breakin", "password", details);
		listener.onApplicationEvent(new UserNotFoundEvent(req));
		verify(auditor).userNotFound("breakin", details);
	}

	@Test
	public void successfulUserAuthenticationIsAudited() throws Exception {
		listener.onApplicationEvent(new UserAuthenticationSuccessEvent(user, mock(Authentication.class)));
		verify(auditor).userAuthenticationSuccess(user, null);
	}

	@Test
	public void failedUserAuthenticationIsAudited() throws Exception {
		AuthzAuthenticationRequest req = new AuthzAuthenticationRequest("auser", "password", details);
		listener.onApplicationEvent(new UserAuthenticationFailureEvent(user, req));
		verify(auditor).userAuthenticationFailure(user, details);
	}

}
