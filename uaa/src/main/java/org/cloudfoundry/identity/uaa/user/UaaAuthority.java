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
 * @author Luke Taylor
 * @author Dave Syer
 */
public enum UaaAuthority implements GrantedAuthority {
	ROLE_ADMIN(1),
	ROLE_USER(0);

	public static final List<UaaAuthority> ADMIN_AUTHORITIES = Collections.unmodifiableList(Arrays.asList(ROLE_ADMIN, ROLE_USER));
	public static final List<UaaAuthority> USER_AUTHORITIES = Collections.unmodifiableList(Arrays.asList(ROLE_USER));
	private final int value;
	
	private UaaAuthority(int value) {
		this.value = value;
	}
	
	public int value() {
		return value;
	}

	@Override
	public String getAuthority() {
		return name();
	}
}
