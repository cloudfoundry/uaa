/*
 * Copyright 2006-2010 the original author or authors.
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
package org.cloudfoundry.identity.app.web;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

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
		String userName = map.get("user_name");
		List<GrantedAuthority> authorities = Arrays.<GrantedAuthority> asList(new SimpleGrantedAuthority("ROLE_USER"));
		CustomUserDetails user = new CustomUserDetails(userName, authorities);
		user.setEmail(map.get("user_email"));
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
