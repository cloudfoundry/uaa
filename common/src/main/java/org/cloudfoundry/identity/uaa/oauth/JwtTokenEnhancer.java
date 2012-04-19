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

import java.util.Collections;

import org.codehaus.jackson.map.ObjectMapper;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.MacSigner;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * OAuth2 token services that produces JWT encoded token values.
 * 
 * @author Dave Syer
 */
public class JwtTokenEnhancer implements TokenEnhancer {

	private AccessTokenConverter tokenConverter = new DefaultTokenConverter();

	private ObjectMapper objectMapper = new ObjectMapper();

	private String key = new RandomValueStringGenerator().generate();
	
	/**
	 * @return the key used when signing tokens
	 */
	@RequestMapping(value = "/token_key", method = RequestMethod.GET)
	@ResponseBody
	public String getKey() {
		return key;
	}

	/**
	 * @param key the key to use when signing tokens
	 */
	@RequestMapping(value = "/token_key", method = RequestMethod.POST)
	@ResponseBody
	public void setKey(@RequestParam String key) {
		this.key = key;
	}
	
	public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
		DefaultOAuth2AccessToken result = new DefaultOAuth2AccessToken(accessToken);
		String tokenId = result.getValue();
		result.setAdditionalInformation(Collections.<String, Object> singletonMap("token_id", tokenId));
		return result.setValue(createAccessTokenValue(accessToken, authentication));
	}

	protected String createAccessTokenValue(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
		String content;
		try {
			content = objectMapper.writeValueAsString(tokenConverter.convertAccessToken(accessToken, authentication));
		}
		catch (Exception e) {
			throw new IllegalStateException("Cannot convert access token to JSON", e);
		}
		String token = JwtHelper.encode(content, new MacSigner(key)).getEncoded();
		return token;
	}

}
