package org.cloudfoundry.identity.uaa.authentication;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;

/**
 * Authentication request object which contains the JSON data submitted to the /authorize endpoint.
 */
public class AuthzAuthenticationRequest implements Authentication {
	private final String username;
	private final String password;

	AuthzAuthenticationRequest(Map<String,String> loginInfo) {
		// Currently only support username/password authentication
		username = loginInfo.get("username").trim();
		password = loginInfo.get("password");
		Assert.hasText("username", "username cannot be empty");
		Assert.hasText("password", "password cannot be empty");
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
		return null;
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
