/**
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
package org.cloudfoundry.identity.uaa.authentication.manager;

import java.net.ProxySelector;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.http.HttpResponse;
import org.apache.http.client.CookieStore;
import org.apache.http.cookie.Cookie;
import org.apache.http.impl.client.DefaultConnectionKeepAliveStrategy;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.conn.ProxySelectorRoutePlanner;
import org.apache.http.impl.conn.tsccm.ThreadSafeClientConnManager;
import org.apache.http.protocol.HttpContext;
import org.cloudfoundry.identity.uaa.authentication.LegacyAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.event.UserAuthenticationFailureEvent;
import org.cloudfoundry.identity.uaa.event.UserAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.user.LegacyUaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
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

	private final RestTemplate restTemplate;

	private final DefaultHttpClient httpClient;

	public LegacyAuthenticationManager() {
		ThreadSafeClientConnManager connectionManager = new ThreadSafeClientConnManager();

		httpClient = new DefaultHttpClient(connectionManager);
		httpClient.setCookieStore(new NullCookieStore());
		httpClient.setKeepAliveStrategy(new KeepAliveStrategy());

		// Use standard JRE proxy configuration.
		httpClient.setRoutePlanner(new ProxySelectorRoutePlanner(connectionManager.getSchemeRegistry(),
					ProxySelector.getDefault()));

		HttpComponentsClientHttpRequestFactory rf = new HttpComponentsClientHttpRequestFactory(httpClient);

		// Set timeout to the default value used by HttpComponentsClientHttpRequestFactory
		rf.setReadTimeout(60*1000);
		setMaxConnections(100);

		restTemplate = new RestTemplate(rf);
	}

	public void setCloudControllerUrl(String url) {
		this.url = url;
	}

	public Authentication authenticate(Authentication authentication) throws AuthenticationException {

		String username = authentication.getName();
		String password = authentication.getCredentials().toString();

		Map<String, String> result;
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
			Map<String, String> object = restTemplate.postForObject(url, request, Map.class, username);
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

	/**
	 * The maximum number of pooled connections which the UAA should use to call the CC.
	 */
	public void setMaxConnections(int maxConnections) {
		((ThreadSafeClientConnManager)httpClient.getConnectionManager()).setMaxTotal(maxConnections);
		((ThreadSafeClientConnManager)httpClient.getConnectionManager()).setDefaultMaxPerRoute(maxConnections);
	}

	private static class NullCookieStore implements CookieStore {
		public void addCookie(Cookie cookie) {
		}

		public List<Cookie> getCookies() {
			return Collections.emptyList();
		}

		public boolean clearExpired(Date date) {
			return false;
		}

		public void clear() {
		}
	}

	/**
	 * Conservative keep-alive strategy that replaces the default (infinite) timeout when
	 * no value is supplied
	 * by the server with a 30s value.
	 */
	private static class KeepAliveStrategy extends DefaultConnectionKeepAliveStrategy {
		@Override
		public long getKeepAliveDuration(HttpResponse response, HttpContext context) {
			long value = super.getKeepAliveDuration(response, context);

			return value < 0 ? 30000 : value;
		}
	}
}
