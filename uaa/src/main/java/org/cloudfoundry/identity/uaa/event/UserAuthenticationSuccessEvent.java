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

import org.cloudfoundry.identity.uaa.audit.UaaAuditService;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.springframework.security.core.Authentication;

/**
 * @author Luke Taylor
 */
public class UserAuthenticationSuccessEvent extends AbstractUaaAuthenticationEvent {
	private final UaaUser user;

	public UserAuthenticationSuccessEvent(UaaUser user, Authentication authentication) {
		super(authentication);
		this.user = user;
	}

	@Override
	void process(UaaAuditService auditor) {
		auditor.userAuthenticationSuccess(user, (UaaAuthenticationDetails) getAuthentication().getDetails());
	}
}
