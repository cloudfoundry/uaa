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
package org.cloudfoundry.identity.uaa.authentication;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.web.authentication.WebAuthenticationDetails;

/**
 * Contains additional information about the authentication request which may be of use in auditing etc.
 * 
 * @author Luke Taylor
 * @author Dave Syer
 */
public class UaaAuthenticationDetails {

	private final String origin;

	private String sessionId;

	public UaaAuthenticationDetails(HttpServletRequest request) {
		WebAuthenticationDetails webAuthenticationDetails = new WebAuthenticationDetails(request);
		this.origin = webAuthenticationDetails.getRemoteAddress();
		this.sessionId = webAuthenticationDetails.getSessionId();
	}

	public String getOrigin() {
		return origin;
	}

	public String getSessionId() {
		return sessionId;
	}
}
