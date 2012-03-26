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
package org.cloudfoundry.identity.app.web;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.http.AccessTokenRequiredException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.web.client.RestOperations;

/**
 * A filter that can authenticate with a remote OpenId Connect provider.
 * 
 * @author Dave Syer
 * 
 */
public class OpenIdClientFilter extends AbstractAuthenticationProcessingFilter {

	public RestOperations restTemplate;

	private String userInfoUrl;

	/**
	 * A rest template to be used to contact the remote user info endpoint.
	 * 
	 * @param restTemplate a rest template
	 */
	public void setRestTemplate(RestOperations restTemplate) {
		this.restTemplate = restTemplate;
	}

	/**
	 * The remote URL of the OpenId Connect /userinfo endpoint.
	 * 
	 * @param userInfoUrl
	 */
	public void setUserInfoUrl(String userInfoUrl) {
		this.userInfoUrl = userInfoUrl;
	}

	public OpenIdClientFilter(String defaultFilterProcessesUrl) {
		super(defaultFilterProcessesUrl);
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException, IOException, ServletException {
		@SuppressWarnings("unchecked")
		Map<String, String> map = restTemplate.getForObject(userInfoUrl, Map.class);
		if (!map.containsKey("user_id")) {
			throw new BadCredentialsException("User info does not contain user_id");
		}
		String userId = map.get("user_id");
		List<GrantedAuthority> authorities = Arrays.<GrantedAuthority> asList(new SimpleGrantedAuthority("ROLE_USER"));
		CustomUserDetails user = new CustomUserDetails(userId, authorities);
		if (map.containsKey("email")) {
			user.setEmail(map.get("email"));
		}
		if (map.containsKey("name")) {
			user.setName(map.get("name"));
		}
		return new UsernamePasswordAuthenticationToken(user, null, authorities);
	}

	@Override
	protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException failed) throws IOException, ServletException {
		if (failed instanceof AccessTokenRequiredException) {
			// Need to force a redirect via the OAuth2 client filter, so rethrow here
			throw failed;
		}
		else {
			// If the exception is not a Spring Security exception this will result in a default error page
			super.unsuccessfulAuthentication(request, response, failed);
		}
	}

}
