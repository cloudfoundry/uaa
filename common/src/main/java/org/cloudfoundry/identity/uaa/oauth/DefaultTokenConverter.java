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
package org.cloudfoundry.identity.uaa.oauth;

import java.util.HashMap;
import java.util.Map;

import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.openid.UserInfo;
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

		}
		response.put(OAuth2AccessToken.SCOPE, token.getScope());
		if (token.getExpiresIn() > 0) {
			response.put(OAuth2AccessToken.EXPIRES_IN, token.getExpiresIn());
		}

		if (token.getExpiration() != null) {
			response.put("expires_at", token.getExpiration().getTime()/1000);
		}
		
		response.putAll(token.getAdditionalInformation());

		response.put("client_id", clientToken.getClientId());
		if (clientToken.getResourceIds() != null && !clientToken.getResourceIds().isEmpty()) {
			response.put("resource_ids", clientToken.getResourceIds());
		}
		return response;
	}

}
