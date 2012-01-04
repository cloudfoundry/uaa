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

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.cloudfoundry.identity.uaa.event.UserAuthenticationFailureEvent;
import org.cloudfoundry.identity.uaa.event.UserAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.util.StringUtils;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

/**
 * Provider which delegates authentication to an existing api for user accounts.
 *
 * By default the {@link #setCloudControllerUrl(String) url} points to the cloud controller on
 * cloudfoundry.com. The remote api is a cloud controller, so it accepts <code>(email, password)</code>
 * form inputs and returns a token as a JSON property "token". The token is added to the successful
 * <tt>LegacyAuthentication</tt> instance.
 *
 * @author Dave Syer
 * @author Luke Taylor
 */
public class LegacyAuthenticationManager implements AuthenticationManager, ApplicationEventPublisherAware {

	private String url = "http://api.cloudfoundry.com/users/{username}/tokens";

	private UaaUserDatabase userDatabase = new LegacyUaaUserDatabase();

	private ApplicationEventPublisher eventPublisher;

	public void setCloudControllerUrl(String url) {
		this.url = url;
	}

	public Authentication authenticate(Authentication authentication) throws AuthenticationException {

		String username = authentication.getName();
		String password = authentication.getCredentials().toString();

		Map<String, String> result = null;
		try {
			result = doAuthentication(username, password);
		}
		catch (AuthenticationException e) {
			eventPublisher.publishEvent(new UserAuthenticationFailureEvent(
					userDatabase.retrieveUserByName(username), authentication));
			throw e;
		}
		UaaUser user = userDatabase.retrieveUserByName(username);
		Authentication success = new LegacyAuthentication(new UaaPrincipal(user),
					user.getAuthorities(), (UaaAuthenticationDetails) authentication.getDetails(), result);
		eventPublisher.publishEvent(new UserAuthenticationSuccessEvent(user, success));

		return success;
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
			throw new BadCredentialsException("Bad credentials");
		}

		if (StringUtils.hasLength(result.get("token"))) {
			result.put("tokenized", "true");
		}
		return result;
	}

	@Override
	public void setApplicationEventPublisher(ApplicationEventPublisher eventPublisher) {
		this.eventPublisher = eventPublisher;
	}

}
