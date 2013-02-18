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

import java.util.Collection;
import java.util.Collections;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
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
			return false;
		}

		return ((OAuth2Authentication) a).isClientOnly();
	}

	@Override
	public boolean isUser() {
		Authentication a = SecurityContextHolder.getContext().getAuthentication();

		if (a instanceof OAuth2Authentication) {
			return !isClient();
		}
		
		if (a instanceof UaaAuthentication) {
			return true;
		}

		return false;
	}

	@Override
	public boolean isAdmin() {
		Authentication a = SecurityContextHolder.getContext().getAuthentication();
		return a!=null && AuthorityUtils.authorityListToSet(a.getAuthorities()).contains("uaa.admin");
	}

	@Override
	public String getUserId() {
		Authentication a = SecurityContextHolder.getContext().getAuthentication();
		return a==null ? null : ((UaaPrincipal) a.getPrincipal()).getId();
	}
	
	@Override
	public String getUserName() {
		Authentication a = SecurityContextHolder.getContext().getAuthentication();
		return a==null ? null : a.getName();
	}

	@Override
	public String getAuthenticationInfo() {
		Authentication a = SecurityContextHolder.getContext().getAuthentication();

		if (a instanceof OAuth2Authentication) {
			OAuth2Authentication oauth = ((OAuth2Authentication) a);

			String info = getClientId();
			if (!oauth.isClientOnly()) {
				info = info + "; " + a.getName() + "; " + getUserId();
			}

			return info;
		} else {
			return a.getName();
		}
	}

	@Override
	public String getClientId() {
		Authentication a = SecurityContextHolder.getContext().getAuthentication();

		if (!(a instanceof OAuth2Authentication)) {
			return null;
		}

		return ((OAuth2Authentication) a).getAuthorizationRequest().getClientId();
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		Authentication a = SecurityContextHolder.getContext().getAuthentication();
		return a == null ? Collections.<GrantedAuthority>emptySet() : a.getAuthorities();
	}

}
