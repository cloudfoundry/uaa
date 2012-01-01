/*
 * Copyright 2002-2011 the original author or authors.
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

package org.cloudfoundry.identity.uaa.authentication;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.util.StringUtils;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.WebUtils;

/**
 * Provider which delegates authentication to an existing api for user accounts. By default the
 * {@link #setCloudControllerUrl(String) url} points to the cloud controller on cloudfoundry.com. The remote api is a
 * cloud controller, so it accpets <code>(email, password)</code> form inputs and returns a token as a JSON property
 * "token". The token is added to the successful {@link Authentication#getDetails() authentication details} as a map
 * entry (i.e. the details are a map).
 * 
 * @author Dave Syer
 */
public class LegacyAuthenticationProvider implements AuthenticationProvider,
		AuthenticationDetailsSource<HttpServletRequest, Map<String, String>> {

	private String url = "http://api.cloudfoundry.com/users/{username}/tokens";

	private MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

	private List<String> parameterKeys = Arrays.asList("email", "password");

	private UaaUserDatabase userDatabase = new LegacyUaaUserDatabase();

	public void setCloudControllerUrl(String url) {
		this.url = url;
	}

	public Authentication authenticate(Authentication authentication) throws AuthenticationException {

		UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = (UsernamePasswordAuthenticationToken) authentication;
		String username = usernamePasswordAuthenticationToken.getName();
		String password = usernamePasswordAuthenticationToken.getCredentials().toString();

		Map<String, String> details = extractDetails(usernamePasswordAuthenticationToken);

		Map<String, String> result = doAuthentication(username, password);
		result.putAll(details);

		UaaUser user = userDatabase.retrieveUserByName(username);
		Authentication success = new UaaAuthentication(new UaaPrincipal(user), user.getAuthorities(), result);

		return success;

	}

	public boolean supports(Class<?> authentication) {
		return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
	}

	private Map<String, String> doAuthentication(String username, String password) {

		Map<String, String> body = new HashMap<String, String>();
		body.put("password", password);

		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
		headers.setContentType(MediaType.APPLICATION_JSON);

		@SuppressWarnings("rawtypes")
		HttpEntity<Map> request = new HttpEntity<Map>(body, headers);

		Map<String, String> result;
		try {
			@SuppressWarnings("unchecked")
			Map<String, String> object = new RestTemplate().postForObject(url, request, Map.class, username);
			result = new HashMap<String, String>(object);
		}
		catch (HttpClientErrorException e) {
			throw new BadCredentialsException(messages.getMessage(
					"AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"));
		}

		if (StringUtils.hasLength(result.get("token"))) {
			result.put("tokenized", "true");
		}
		return result;
	}

	public Map<String, String> buildDetails(HttpServletRequest context) {
		WebAuthenticationDetails webAuthenticationDetails = new WebAuthenticationDetails(context);
		Map<String, String> map = new HashMap<String, String>();
		map.put("remote_addess", webAuthenticationDetails.getRemoteAddress());
		map.put("session_id", webAuthenticationDetails.getSessionId());
		@SuppressWarnings("unchecked")
		Map<String, String[]> parameterMap = context.getParameterMap();
		for (String key : parameterKeys) {
			if (parameterMap.containsKey(key)) {
				map.put(key, WebUtils.findParameterValue(parameterMap, key));
			}
		}
		return map;
	}

	@SuppressWarnings("unchecked")
	private Map<String, String> extractDetails(Authentication authentication) {
		return authentication.getDetails() instanceof Map ? new HashMap<String, String>(
				(Map<String, String>) authentication.getDetails()) : new HashMap<String, String>();
	}

}
