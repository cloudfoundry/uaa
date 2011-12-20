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

import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.user.UaaUser;

/**
 * Service interface which handles the different types of audit event raised by the system.
 */
public interface UaaAuditService {
	/**
	 * Authentication of a specific user, i.e. a person
	 */
	void userAuthenticationSuccess(UaaUser user, UaaAuthenticationDetails details);

	void userAuthenticationFailure(UaaUser user, UaaAuthenticationDetails details);

	void userNotFound(String name, UaaAuthenticationDetails details);

	/**
	 * Authentication of any other (non-user) principal.
	 */
//	void principalAuthenticationSuccess(String name);
//
//	void principalAuthenticationFailure(String name);
//
//	void principalNotFound(String name);
}
