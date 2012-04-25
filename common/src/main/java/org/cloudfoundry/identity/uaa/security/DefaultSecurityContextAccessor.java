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
package org.cloudfoundry.identity.uaa.security;

import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

/**
 * @author Luke Taylor
 * @author Dave Syer
 */
public class DefaultSecurityContextAccessor implements SecurityContextAccessor {

	@Override
	public boolean isClient() {
		Authentication a = SecurityContextHolder.getContext().getAuthentication();

		if (!(a instanceof OAuth2Authentication)) {
			throw new IllegalStateException("Must be an OAuth2Authentication to check if user is a client");
		}

		return ((OAuth2Authentication) a).isClientOnly();
	}

	@Override
	public boolean isAdmin() {
		Authentication a = SecurityContextHolder.getContext().getAuthentication();
		return AuthorityUtils.authorityListToSet(a.getAuthorities()).contains("ROLE_ADMIN");
	}

	@Override
	public String getUserId() {
		Authentication a = SecurityContextHolder.getContext().getAuthentication();
		return ((UaaPrincipal) a.getPrincipal()).getId();
	}
	
	@Override
	public String getClientId() {
		Authentication a = SecurityContextHolder.getContext().getAuthentication();

		if (!(a instanceof OAuth2Authentication)) {
			throw new IllegalStateException("Must be an OAuth2Authentication to check if user is a client");
		}

		return ((OAuth2Authentication) a).getAuthorizationRequest().getClientId();
	}

}
