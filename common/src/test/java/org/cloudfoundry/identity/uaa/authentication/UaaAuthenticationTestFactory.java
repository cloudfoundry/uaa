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

import org.cloudfoundry.identity.uaa.user.MockUaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;

/**
 * @author Dave Syer
 * 
 */
public class UaaAuthenticationTestFactory {

	public static UaaPrincipal getPrincipal(String id, String name, String email) {
		return new UaaPrincipal(new MockUaaUserDatabase(id, name, email, name, "unknown").retrieveUserByName(name));
	}

	public static UaaAuthentication getAuthentication(String id, String name, String email) {
		return new UaaAuthentication(getPrincipal(id, name, email), UaaAuthority.USER_AUTHORITIES, null);
	}

	public static AuthzAuthenticationRequest getAuthenticationRequest(String name) {
		return new AuthzAuthenticationRequest(name, "password", null);
	}

}
