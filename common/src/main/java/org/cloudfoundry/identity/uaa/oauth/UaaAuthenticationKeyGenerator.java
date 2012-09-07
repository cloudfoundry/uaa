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

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.AuthenticationKeyGenerator;

/**
 * @author Dave Syer
 * 
 */
public class UaaAuthenticationKeyGenerator implements AuthenticationKeyGenerator {

	private static final String CLIENT_ID = "client_id";

	private static final String SCOPE = "scope";

	private static final String ACCESS_TOKEN_VALIDITY = "access_token_validity";

	private static final String REFRESH_TOKEN_VALIDITY = "refresh_token_validity";

	private UserTokenConverter userTokenConverter = new UaaUserTokenConverter();

	private ClientDetailsService clientDetailsService;

	/**
	 * @param clientDetailsService the clientDetailsService to set
	 */
	public void setClientDetailsService(ClientDetailsService clientDetailsService) {
		this.clientDetailsService = clientDetailsService;
	}

	@Override
	public String extractKey(OAuth2Authentication authentication) {
		Map<String, Object> values = new LinkedHashMap<String, Object>();
		AuthorizationRequest authorizationRequest = authentication.getAuthorizationRequest();
		if (!authentication.isClientOnly()) {
			values.putAll(userTokenConverter.convertUserAuthentication(authentication.getUserAuthentication()));
		}
		ClientDetails client = clientDetailsService.loadClientByClientId(authorizationRequest.getClientId());
		values.put(CLIENT_ID, client.getClientId());
		if (authorizationRequest.getScope() != null) {
			values.put(SCOPE, OAuth2Utils.formatParameterList(authorizationRequest.getScope()));
		}
		Integer validity = client.getAccessTokenValiditySeconds();
		if (validity != null) {
			values.put(ACCESS_TOKEN_VALIDITY, validity);
		}
		validity = client.getRefreshTokenValiditySeconds();
		if (validity != null && client.getAuthorizedGrantTypes().contains("refresh_token")) {
			values.put(REFRESH_TOKEN_VALIDITY, validity);
		}
		MessageDigest digest;
		try {
			digest = MessageDigest.getInstance("MD5");
		}
		catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("MD5 algorithm not available.  Fatal (should be in the JDK).");
		}

		try {
			byte[] bytes = digest.digest(values.toString().getBytes("UTF-8"));
			return String.format("%032x", new BigInteger(1, bytes));
		}
		catch (UnsupportedEncodingException e) {
			throw new IllegalStateException("UTF-8 encoding not available.  Fatal (should be in the JDK).");
		}
	}

}
