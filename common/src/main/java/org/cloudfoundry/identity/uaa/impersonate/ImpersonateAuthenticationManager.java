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

package org.cloudfoundry.identity.uaa.impersonate;

import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

/**
 * @author Dave Syer
 * 
 */
public class ImpersonateAuthenticationManager implements AuthenticationManager {

	private final UaaUserDatabase userDatabase;

	public ImpersonateAuthenticationManager(UaaUserDatabase userDatabase) {
		this.userDatabase = userDatabase;
	}

	@Override
	public Authentication authenticate(Authentication request) throws AuthenticationException {

		if (request instanceof UsernamePasswordAuthenticationToken) {
			UsernamePasswordAuthenticationToken userAuth = (UsernamePasswordAuthenticationToken) request;
			// We know by now that the request is legitimate and we just need to switch to the impersonated user
			UaaUser user = userDatabase.retrieveUserByName(userAuth.getName());
			UaaPrincipal principal = new UaaPrincipal(user);
			return new UsernamePasswordAuthenticationToken(principal, "<none>", user.getAuthorities());
		}

		return null;

	}

}
