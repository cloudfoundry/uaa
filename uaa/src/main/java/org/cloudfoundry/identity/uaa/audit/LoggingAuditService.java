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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.user.UaaUser;

/**
 * Audit service implementation which just outputs the relevant
 * information through the logger.
 *
 * @author Luke Taylor
 */
public class LoggingAuditService implements UaaAuditService {
	private final Log logger = LogFactory.getLog("UAA Audit Logger");

	@Override
	public void userAuthenticationSuccess(UaaUser user) {
		log("User authenticated: " + user.getId() + ", " + user.getUsername());
	}

	@Override
	public void userAuthenticationFailure(UaaUser user) {
		log("Authentication failed, user: " + user.getId() + ", " + user.getUsername());
	}

	@Override
	public void userNotFound(String name) {
		log("Attempt to login as non-existent user: " + name);
	}

//	@Override
//	public void principalAuthenticationSuccess(String name) {
//		log("Principal authenticated: " + name);
//	}
//
//	@Override
//	public void principalAuthenticationFailure(String name) {
//		log("Authentication failed, principal: " + name);
//	}
//
//	@Override
//	public void principalNotFound(String name) {
//		log("Attempt to login as non-existent principal: " + name);
//	}

	private void log(String msg) {
		StringBuilder output = new StringBuilder(256);
  		output.append("\n\n************************************************************\n\n");
		output.append(msg).append("\n");
		output.append("\n\n************************************************************\n\n");
		logger.info(output.toString());
	}
}
