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
package org.cloudfoundry.identity.uaa.security;

import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * @author Luke Taylor
 */
public class DefaultSecurityContextAccessor implements SecurityContextAccessor {
	@Override
	public boolean currentUserHasId(String id) {
		Authentication a = SecurityContextHolder.getContext().getAuthentication();

		return a != null && id.equals(((UaaPrincipal)a.getPrincipal()).getId());
	}
}
