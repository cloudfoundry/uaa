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
