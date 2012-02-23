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

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.openid.UserInfo;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

/**
 * @author Dave Syer
 *
 */
public class DefaultTokenConverter implements AccessTokenConverter {

	@Override
	public Map<String, Object> convertAccessToken(OAuth2AccessToken token, OAuth2Authentication authentication) {
		Map<String, Object> response = new HashMap<String, Object>();
		AuthorizationRequest clientToken = authentication.getAuthorizationRequest();

		if (!authentication.isClientOnly()
				&& authentication.getUserAuthentication().getPrincipal() instanceof UaaPrincipal) {

			UaaPrincipal principal = (UaaPrincipal) authentication.getUserAuthentication().getPrincipal();

			response.put("id", principal.getId());
			response.put(UserInfo.USER_ID, principal.getName());
			response.put(UserInfo.EMAIL, principal.getEmail());
			Collection<? extends GrantedAuthority> authorities = authentication.getUserAuthentication()
					.getAuthorities();
			if (authorities != null) {
				response.put("user_authorities", getAuthorities(authorities));
			}

		}
		response.put(OAuth2AccessToken.SCOPE, token.getScope());
		if (token.getExpiresIn() > 0) {
			response.put(OAuth2AccessToken.EXPIRES_IN, token.getExpiresIn());
		}

		response.put("client_id", clientToken.getClientId());
		if (clientToken.getAuthorities() != null) {
			response.put("client_authorities", getAuthorities(clientToken.getAuthorities()));
		}
		if (clientToken.getResourceIds() != null && !clientToken.getResourceIds().isEmpty()) {
			response.put("resource_ids", clientToken.getResourceIds());
		}
		return response;
	}

	private Collection<String> getAuthorities(Collection<? extends GrantedAuthority> authorities) {
		Collection<String> result = new ArrayList<String>();
		for (GrantedAuthority authority : authorities) {
			result.add(authority.getAuthority());
		}
		return result;
	}

}
