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

import java.util.Map;

import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.type.TypeReference;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.stereotype.Controller;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * Controller which decodes access tokens for clients who are not able to do so (or where opaque token values are used).
 *
 * @author Luke Taylor
 */
@Controller
public class CheckTokenEndpoint implements InitializingBean {

	private ResourceServerTokenServices resourceServerTokenServices;
	private ObjectMapper mapper = new ObjectMapper();

	public void setTokenServices(ResourceServerTokenServices resourceServerTokenServices) {
		this.resourceServerTokenServices = resourceServerTokenServices;
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		Assert.notNull(resourceServerTokenServices, "tokenServices must be set");
	}

	@RequestMapping(value = "/check_token")
	@ResponseBody
	public Map<String, ?> checkToken(@RequestParam("token") String value) {

		OAuth2AccessToken token = resourceServerTokenServices.readAccessToken(value);
		if (token == null) {
			throw new InvalidTokenException("Token was not recognised");
		}

		if (token.isExpired()) {
			throw new InvalidTokenException("Token has expired");
		}

		Map<String, ?> response = getClaimsForToken(value);

		return response;
	}

	private Map<String, Object> getClaimsForToken(String token) {
		Jwt tokenJwt = null;
		try {
			tokenJwt = JwtHelper.decode(token);
		} catch (Throwable t) {
			throw new InvalidTokenException("Invalid token (could not decode): " + token);
		}

		Map<String, Object> claims = null;
		try {
			claims = mapper.readValue(tokenJwt.getClaims(), new TypeReference<Map<String, Object>>() {});
		}
		catch (Exception e) {
			throw new IllegalStateException("Cannot read token claims", e);
		}

		return claims;
	}
}
