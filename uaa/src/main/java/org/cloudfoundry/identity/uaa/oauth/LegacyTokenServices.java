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
package org.cloudfoundry.identity.uaa.oauth;

import org.cloudfoundry.identity.uaa.authentication.LegacyAuthentication;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.RandomValueTokenServices;
import org.springframework.util.Assert;

/**
 * OAuth2 token services for authorization and resource server.
 * 
 * Assumes that the user authentication is a <tt>LegacyAuthentication</tt> instance and uses the token value obtained
 * from it to create the access token.
 * 
 * @author Dave Syer
 * @author Luke Taylor
 */
public class LegacyTokenServices extends RandomValueTokenServices {

	@Override
	public void afterPropertiesSet() throws Exception {
		super.afterPropertiesSet();
		setSupportRefreshToken(false);
	}

	@Override
	protected OAuth2AccessToken createAccessToken(OAuth2Authentication authentication, OAuth2RefreshToken refreshToken) {

		OAuth2AccessToken accessToken = super.createAccessToken(authentication, refreshToken);
		if (authentication.getUserAuthentication() == null) {
			return accessToken;
		}

		if (!(authentication.getUserAuthentication() instanceof LegacyAuthentication)) {
			throw new IllegalStateException("Expected a LegacyAuthentication instance for the user authentication");
		}

		String token = ((LegacyAuthentication) authentication.getUserAuthentication()).getToken();

		OAuth2AccessToken result = new OAuth2AccessToken(token);
		result.setScope(accessToken.getScope());
		result.setExpiration(accessToken.getExpiration());

		// This token is no longer a random value, so we'd better check that we haven't already stored it with a
		// different authentication
		checkForDuplicates(result, authentication);
		return result;
	}

	private void checkForDuplicates(OAuth2AccessToken token, OAuth2Authentication authentication) {
		OAuth2Authentication existingAuthentication = null;
		try {
			existingAuthentication = loadAuthentication(token.getValue());
		}
		catch (InvalidTokenException e) {
			return;
		}
		if (existingAuthentication != null) {
			Assert.state(existingAuthentication.equals(authentication),
					"Internal error: duplicate authentications with different values for same token");
		}
	}

}
