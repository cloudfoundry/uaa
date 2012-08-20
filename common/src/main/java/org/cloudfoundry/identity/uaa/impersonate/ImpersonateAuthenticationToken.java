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

import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.util.Assert;

/**
 * Authentication request object representing an authenticated request to obtain an impersonated token.
 * 
 * @author Dave Syer
 */
public class ImpersonateAuthenticationToken extends OAuth2Authentication {

	private final String clientId;

	private final String username;

	public ImpersonateAuthenticationToken(OAuth2Authentication authentication) {
		super(authentication.getAuthorizationRequest(), authentication.getUserAuthentication());
		this.clientId = authentication.getAuthorizationRequest().getClientId();
		this.username = authentication.isClientOnly() ? null : authentication.getUserAuthentication().getName();
		Assert.hasText("clientId", "clientId cannot be empty");
	}
	
	@Override
	public String getName() {
		return clientId;
	}

	public String getClientId() {
		return clientId;
	}
	
	public String getUsername() {
		return username;
	}

}
