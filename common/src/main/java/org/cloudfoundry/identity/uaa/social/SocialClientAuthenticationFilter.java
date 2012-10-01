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
import java.util.Collection;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.http.AccessTokenRequiredException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.util.Assert;

/**
 * @author Dave Syer
 * 
 */
public class SocialClientAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

	private SocialClientUserDetailsSource socialClientUserDetailsSource;
	
	/**
	 * @param socialClientUserDetailsSource the socialClientUserDetailsSource to set
	 */
	public void setSocialClientUserDetailsSource(SocialClientUserDetailsSource socialClientUserDetailsSource) {
		this.socialClientUserDetailsSource = socialClientUserDetailsSource;
	}

	@Override
	public void afterPropertiesSet() {
		Assert.state(socialClientUserDetailsSource != null, "User info source must be provided");
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
		SocialClientUserDetails user = socialClientUserDetailsSource.getUserDetails();
		Collection<GrantedAuthority> authorities = user.getAuthorities();
		UsernamePasswordAuthenticationToken result;
		if (authorities != null && !authorities.isEmpty()) { // TODO: correlate user data with existing accounts if email or username missing
			result = new UsernamePasswordAuthenticationToken(user, null, authorities);
		}
		else {
			// Unauthenticated
			result = new UsernamePasswordAuthenticationToken(user, null);
		}
		result.setDetails(authenticationDetailsSource.buildDetails(request));
		return result;
	}

	@Override
	protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException failed) throws IOException, ServletException {
		if (failed instanceof AccessTokenRequiredException
				|| failed instanceof org.springframework.security.oauth.consumer.AccessTokenRequiredException) {
			// Need to force a redirect via the OAuth client filter, so rethrow here
			throw failed;
		}
		else {
			// If the exception is not a Spring Security exception this will result in a default error page
			super.unsuccessfulAuthentication(request, response, failed);
		}
	}

}
