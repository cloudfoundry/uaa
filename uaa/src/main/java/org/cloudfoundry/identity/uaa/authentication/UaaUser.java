package org.cloudfoundry.identity.uaa.authentication;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

import java.util.List;

/**
 * User data for authentication against UAA's internal authentication provider.
 * 
 * @author Luke Taylor
 * @author Dave Syer
 */
public class UaaUser {

	private final String username;

	private final String password;

	private final String email;

	private List<GrantedAuthority> authorities = AuthorityUtils.createAuthorityList("ROLE_USER");

	public UaaUser(String username, String password) {
		this(username, password, null);
	}

	public UaaUser(String username, String password, String email) {
		this.username = username;
		this.password = password;
		this.email = email;
	}

	public String getUsername() {
		return username;
	}

	public String getPassword() {
		return password;
	}

	public String getEmail() {
		return email;
	}

	public List<GrantedAuthority> getAuthorities() {
		return authorities;
	}
}
