/**
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

import java.util.Arrays;

import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.user.MockUaaUserDatabase;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

/**
 * @author Dave Syer
 *
 */
public class UaaAuthenticationTestFactory {

	public static UaaPrincipal getPrincipal(String id, String name, String email) {
		return new UaaPrincipal(
				new MockUaaUserDatabase(id, name, email, name, "unknown").retrieveUserByName(name));
	}

	public static UaaAuthentication getAuthentication(String id, String name, String email) {
		return new UaaAuthentication(getPrincipal(id, name, email),
				Arrays.<GrantedAuthority> asList(new SimpleGrantedAuthority("ROLE_USER")), null);
	}

	public static ScimUser getScimUser(String name, String email, String givenName, String familyName) {
		ScimUser user = new ScimUser(null, name, givenName, familyName);
		user.addEmail(email);
		return user;
	}

}
