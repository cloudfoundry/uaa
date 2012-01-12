/*
 * Copyright 2006-2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
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

	LegacyAuthentication(UaaPrincipal principal, List<? extends GrantedAuthority> authorities,
						 UaaAuthenticationDetails details, Map<String, String> legacyAuthData) {
		super(principal, authorities, details);
		this.legacyAuthData = legacyAuthData;
	}

	public String getToken() {
		return legacyAuthData.get("token");
	}
}
