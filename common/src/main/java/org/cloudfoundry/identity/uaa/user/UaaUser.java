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
package org.cloudfoundry.identity.uaa.user;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;

/**
 * User data for authentication against UAA's internal authentication provider.
 *
 * @author Luke Taylor
 * @author Dave Syer
 */
public class UaaUser {

	private final String id;

	private final String username;

	private final String password;

	private final String email;

	private final String givenName;

	private final String familyName;

	private final Date created;

	private final Date modified;

	private final List<? extends GrantedAuthority> authorities;

	public UaaUser(String username, String password, String email, String givenName, String familyName) {
		this("NaN", username, password, email, UaaAuthority.USER_AUTHORITIES, givenName, familyName, new Date(),
				new Date());
	}

	public UaaUser(String id, String username, String password, String email, List<? extends GrantedAuthority> authorities,
			String givenName, String familyName, Date created, Date modified) {
		Assert.hasText(username, "Username cannot be empty");
		Assert.hasText(id, "Id cannot be null");
		Assert.hasText(email, "Email is required");
		this.id = id;
		this.username = username;
		this.password = password;
		// TODO: Canonicalize email?
		this.email = email;
		this.familyName = familyName;
		this.givenName = givenName;
		this.created = created;
		this.modified = modified;
		this.authorities = authorities;
	}

	public String getId() {
		return id;
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

	public String getGivenName() {
		return givenName;
	}

	public String getFamilyName() {
		return familyName;
	}

	public List<? extends GrantedAuthority> getAuthorities() {
		return authorities;
	}

	public UaaUser id(String id) {
		if (!"NaN".equals(this.id)) {
			throw new IllegalStateException("Id already set");
		}
		return new UaaUser(id, username, password, email, authorities, givenName, familyName, created, modified);
	}

	public UaaUser authorities(Collection<? extends GrantedAuthority> authorities) {
		ArrayList<GrantedAuthority> values = new ArrayList<GrantedAuthority>(authorities);
		for (int i = 0; i < values.size(); i++) {
			GrantedAuthority authority = values.get(i);
			values.set(i, UaaAuthority.authority(authority.toString()));
		}
		if (!values.contains(UaaAuthority.UAA_USER)) {
			values.add(UaaAuthority.UAA_USER);
		}
		UaaUser user = new UaaUser(id, username, password, email, values, givenName, familyName, created, modified);
		return user;
	}

	@Override
	public String toString() {
		return "[UaaUser {id=" + id + ", username=" + username + ", email=" + email + ", givenName=" + givenName
				+ ", familyName=" + familyName + "}]";
	}

	public Date getModified() {
		return modified;
	}

}
