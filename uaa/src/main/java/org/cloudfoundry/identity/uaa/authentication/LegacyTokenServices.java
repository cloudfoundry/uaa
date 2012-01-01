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
 * OAuth2 token services for authorization and resource server. The token value has to be passed in as part of the
 * authentication details, so it is assumed to be populated during authentication somehow. The authentication details
 * should be a map with the token stored under key "token".
 * 
 * @author Dave Syer
 * 
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

		Map<String, String> details = extractDetails(authentication.getUserAuthentication());
		if (!details.containsKey("token")) {
			throw new IllegalStateException("Expected token to be part of authentication details");
		}

		OAuth2AccessToken result = new OAuth2AccessToken(details.get("token"));
		result.setScope(accessToken.getScope());
		result.setExpiration(accessToken.getExpiration());
		return result;

	}

	@SuppressWarnings("unchecked")
	private Map<String, String> extractDetails(Authentication authentication) {
		return authentication.getDetails() instanceof Map ? new HashMap<String, String>(
				(Map<String, String>) authentication.getDetails()) : new HashMap<String, String>();
	}

}