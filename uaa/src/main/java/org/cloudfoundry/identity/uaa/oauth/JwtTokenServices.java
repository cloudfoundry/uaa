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

import org.codehaus.jackson.map.ObjectMapper;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.MacSigner;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.RandomValueTokenServices;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * OAuth2 token services that produces JWT encoded token values.
 *
 * @author Dave Syer
 */
public class JwtTokenServices extends RandomValueTokenServices {

	private AccessTokenConverter tokenConverter = new DefaultTokenConverter();

	private ObjectMapper objectMapper = new ObjectMapper();

	private String key = new RandomValueStringGenerator().generate();

	/**
	 * @return the key used when signing tokens
	 */
	@RequestMapping(value = "/token_key", method=RequestMethod.GET)
	@ResponseBody
	public String getKey() {
		return key;
	}

	/**
	 * @param key the key to use when signing tokens
	 */
	@RequestMapping(value = "/token_key", method=RequestMethod.POST)
	@ResponseBody
	public void setKey(@RequestParam String key) {
		this.key = key;
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		super.afterPropertiesSet();
		setSupportRefreshToken(false);
	}

	@Override
	protected OAuth2AccessToken createAccessToken(OAuth2Authentication authentication, OAuth2RefreshToken refreshToken) {

		OAuth2AccessToken accessToken = super.createAccessToken(authentication, refreshToken);

		String content;
		try {
			content = objectMapper.writeValueAsString(tokenConverter.convertAccessToken(accessToken, authentication));
		}
		catch (Exception e) {
			throw new IllegalStateException("Cannot convert access token to JSON", e);
		}
		// TODO: use client secret from client details service (but N.B. the audience is the resource server)
		String token = JwtHelper.encode(content , new MacSigner(key)).getEncoded();
		OAuth2AccessToken result = new OAuth2AccessToken(token);
		result.setScope(accessToken.getScope());
		result.setExpiration(accessToken.getExpiration());

		return result;

	}

}
