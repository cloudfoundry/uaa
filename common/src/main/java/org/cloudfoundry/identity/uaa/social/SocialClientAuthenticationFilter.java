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

package org.cloudfoundry.identity.uaa.social;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.http.AccessTokenRequiredException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.util.Assert;
import org.springframework.web.client.RestOperations;

/**
 * @author Dave Syer
 * 
 */
public class SocialClientAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

	public RestOperations restTemplate;

	private String userInfoUrl;

	/**
	 * A rest template to be used to contact the remote user info endpoint. Normally would be an instance of
	 * {@link OAuth2RestTemplate}, but there is no need for that dependency to be explicit, and there are advantages in
	 * making it implicit (e.g. for testing purposes).
	 * 
	 * @param restTemplate a rest template
	 */
	public void setRestTemplate(RestOperations restTemplate) {
		this.restTemplate = restTemplate;
	}

	/**
	 * The remote URL of the <code>/userinfo</code> endpoint or equivalent. This should be a resource on the remote
	 * server that provides user profile data.
	 * 
	 * @param userInfoUrl
	 */
	public void setUserInfoUrl(String userInfoUrl) {
		this.userInfoUrl = userInfoUrl;
	}

	@Override
	public void afterPropertiesSet() {
		Assert.state(userInfoUrl != null, "User info URL must be provided");
		Assert.state(restTemplate != null, "RestTemplate must be provided");
		super.afterPropertiesSet();
	}

	public SocialClientAuthenticationFilter(String defaultFilterProcessesUrl) {
		super(defaultFilterProcessesUrl);
		setAuthenticationManager(new AuthenticationManager() {
			@Override
			public Authentication authenticate(Authentication authentication) throws AuthenticationException {
				throw new IllegalStateException("Not used");
			}
		});
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException, IOException, ServletException {
		@SuppressWarnings("unchecked")
		Map<String, String> map = restTemplate.getForObject(userInfoUrl, Map.class);
		String userName = getUserName(map);
		String email = null;
		if (map.containsKey("email")) {
			email = map.get("email");
		}
		if (userName == null && email != null) {
			userName = email;
		}
		Object userId = map.get("id");
		List<UaaAuthority> authorities = UaaAuthority.USER_AUTHORITIES;
		SocialClientUserDetails user = new SocialClientUserDetails(userName, authorities);
		user.setExternalId(userId);
		if (map.containsKey("name")) {
			user.setName(map.get("name"));
		}
		else if (map.containsKey("formattedName")) {
			user.setName(map.get("formattedName"));
		}
		if (email != null) {
			user.setEmail(email);
		}
		UsernamePasswordAuthenticationToken result;
		if (authorities != null) { // TODO: correlate user data with existing accounts if email or username missing
			result = new UsernamePasswordAuthenticationToken(user, null, authorities);
		}
		else {
			// Unauthenticated
			result = new UsernamePasswordAuthenticationToken(user, null);
		}
		result.setDetails(map);
		return result;
	}

	private String getUserName(Map<String, String> map) {
		String key = "username";
		if (userInfoUrl.contains("github.com")) {
			key = "login";
		}
		if (userInfoUrl.contains("twitter.com")) {
			key = "screen_name";
		}
		if (userInfoUrl.contains("linkedin.com")) {
			key = "id"; // no user-friendly identifier for linked in
		}
		return map.get(key);
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
