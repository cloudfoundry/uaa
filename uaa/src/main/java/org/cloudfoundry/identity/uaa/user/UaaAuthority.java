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
	ROLE_ADMIN,
	ROLE_USER;

	public static final List<UaaAuthority> ADMIN_AUTHORITIES = Collections.unmodifiableList(Arrays.asList(ROLE_ADMIN, ROLE_USER));
	public static final List<UaaAuthority> USER_AUTHORITIES = Collections.unmodifiableList(Arrays.asList(ROLE_USER));

	@Override
	public String getAuthority() {
		return name();
	}
}
