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

import java.util.Collection;
import java.util.Collections;
import java.util.Map;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;

/**
 * Authentication request object which contains the JSON data submitted to the /authorize endpoint.
 *
 * This token is not used to represent an authenticated user.
 *
 * @author Luke Taylor
 */
public class AuthzAuthenticationRequest implements Authentication {
	private final String username;
	private final String password;
	private final UaaAuthenticationDetails details;

	public AuthzAuthenticationRequest(Map<String,String> loginInfo, UaaAuthenticationDetails details) {
		// Currently only support username/password authentication
		this(loginInfo.get("username"), loginInfo.get("password"), details);
		Assert.notNull(details);
	}

	public AuthzAuthenticationRequest(String username, String password, UaaAuthenticationDetails details) {
		Assert.hasText("username", "username cannot be empty");
		Assert.hasText("password", "password cannot be empty");
		this.username = username.trim();
		this.password = password.trim();
		this.details = details;
	}

	public Collection<? extends GrantedAuthority> getAuthorities() {
		return Collections.emptyList();
	}

	public String getPrincipal() {
		return username;
	}

	public String getCredentials() {
		return password;
	}

	public Object getDetails() {
		return details;
	}

	public boolean isAuthenticated() {
		return false;
	}

	public void setAuthenticated(boolean isAuthenticated) {
		if (isAuthenticated) {
			throw new IllegalArgumentException("Authentication request can not be 'authenticated'");
		}
	}

	public String getName() {
		return username;
	}
}
