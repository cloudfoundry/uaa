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
package org.cloudfoundry.identity.uaa.authentication;

import java.io.Serializable;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.web.authentication.WebAuthenticationDetails;

/**
 * Contains additional information about the authentication request which may be of use in auditing etc.
 * 
 * @author Luke Taylor
 * @author Dave Syer
 */
public class UaaAuthenticationDetails implements Serializable {

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
