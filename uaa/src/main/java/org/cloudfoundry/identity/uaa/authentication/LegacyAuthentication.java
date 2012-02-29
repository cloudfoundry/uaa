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

import java.util.List;
import java.util.Map;

import org.springframework.security.core.GrantedAuthority;

/**
 * Extended authentication which contains the legacy token value
 *
 * @author Luke Taylor
 */
public class LegacyAuthentication extends UaaAuthentication {
	private final Map<String, String> legacyAuthData;

	public LegacyAuthentication(UaaPrincipal principal, List<? extends GrantedAuthority> authorities,
						 UaaAuthenticationDetails details, Map<String, String> legacyAuthData) {
		super(principal, authorities, details);
		this.legacyAuthData = legacyAuthData;
	}

	public String getToken() {
		return legacyAuthData.get("token");
	}
}
