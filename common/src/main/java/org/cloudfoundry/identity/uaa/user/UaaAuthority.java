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

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;

/**
 * The UAA only distinguishes 2 types of user for internal usage, denoted <code>uaa.admin</code> and
 * <code>uaa.user</code>. Other authorities might be stored in the back end for the purposes of other resource servers,
 * so this enumeration has convenient methods for extracting the UAA user types from authorities lists.
 * 
 * @author Luke Taylor
 * @author Dave Syer
 */
public enum UaaAuthority implements GrantedAuthority {

	UAA_ADMIN("uaa.admin", 1), UAA_USER("uaa.user", 0), UAA_NONE("uaa.none", -1);

	public static final List<UaaAuthority> ADMIN_AUTHORITIES = Collections.unmodifiableList(Arrays.asList(UAA_ADMIN,
			UAA_USER));

	public static final List<UaaAuthority> USER_AUTHORITIES = Collections.unmodifiableList(Arrays.asList(UAA_USER));

	public static final List<UaaAuthority> NONE_AUTHORITIES = Collections.unmodifiableList(Arrays.asList(UAA_NONE));

	private final int value;

	private final String userType;

	private UaaAuthority(String userType, int value) {
		this.userType = userType;
		this.value = value;
	}

	public int value() {
		return value;
	}

	/**
	 * The name of the type of user, either "uaa.admin" or "uaa.user".
	 * 
	 * @return a user type name
	 */
	public String getUserType() {
		return userType;
	}

	/**
	 * The authority granted by this value (same as user type).
	 * 
	 * @return the name of the value (uaa.user, etc.)
	 * @see org.springframework.security.core.GrantedAuthority#getAuthority()
	 */
	@Override
	public String getAuthority() {
		return userType;
	}
	
	@Override
	public String toString() {
		return userType;
	}

	public static UaaAuthority fromAuthorities(String authorities) {
		String type = authorities == null ? "uaa.user" : authorities.toLowerCase();
		return type.contains("uaa.admin") ? UAA_ADMIN : UAA_USER;
	}
}
