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

import java.util.HashMap;
import java.util.Map;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.RandomValueTokenServices;

/**
 * OAuth2 token services for authorization and resource server.
 *
 * Assumes that the user authentication is a <tt>LegacyAuthentication</tt> instance and uses the
 * token value obtained from it to create the access token.
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

		String token = ((LegacyAuthentication)authentication.getUserAuthentication()).getToken();

		OAuth2AccessToken result = new OAuth2AccessToken(token);
		result.setScope(accessToken.getScope());
		result.setExpiration(accessToken.getExpiration());

		return result;
	}

}
