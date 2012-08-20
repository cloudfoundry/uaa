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

import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;

/**
 * @author Dave Syer
 * 
 */
public class ImpersonateTokenEnhancer implements TokenEnhancer {

	@Override
	public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
		DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken(accessToken);
		Map<String, Object> info = new LinkedHashMap<String, Object>(token.getAdditionalInformation());
		Map<String, Object> impersonator = new LinkedHashMap<String, Object>();
		impersonator.put("client_id",
				authentication.getAuthorizationRequest().getAuthorizationParameters().get("impersonator_client_id"));
		String user_id = authentication.getAuthorizationRequest().getAuthorizationParameters()
				.get("impersonator_user_id");
		if (user_id != null) {
			impersonator.put("user_id", user_id);
		}
		info.put("impersonator", impersonator);
		token.setAdditionalInformation(info);
		return token;
	}

}
