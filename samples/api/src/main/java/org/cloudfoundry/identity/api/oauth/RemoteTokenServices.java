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
package org.cloudfoundry.identity.api.oauth;

import java.io.UnsupportedEncodingException;
import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.util.Assert;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

/**
 * @author Dave Syer
 * 
 */
public class RemoteTokenServices implements ResourceServerTokenServices {

	protected final Log logger = LogFactory.getLog(getClass());

	private RestOperations restTemplate = new RestTemplate();

	private String checkTokenEndpointUrl;

	private String clientId;

	private String clientSecret;

	public void setRestTemplate(RestOperations restTemplate) {
		this.restTemplate = restTemplate;
	}

	public void setCheckTokenEndpointUrl(String checkTokenEndpointUrl) {
		this.checkTokenEndpointUrl = checkTokenEndpointUrl;
	}

	public void setClientId(String clientId) {
		this.clientId = clientId;
	}

	public void setClientSecret(String clientSecret) {
		this.clientSecret = clientSecret;
	}

	public OAuth2Authentication loadAuthentication(String accessToken) throws AuthenticationException {

		MultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
		formData.add("token", accessToken);
		HttpHeaders headers = new HttpHeaders();
		headers.set("Authorization", getAuthorizationHeader(clientId, clientSecret));
		Map<String, Object> map = postForMap(checkTokenEndpointUrl, formData, headers);

		if (map.containsKey("error")) {
			logger.debug("check_token returned error: " + map.get("error"));
			throw new InvalidTokenException(accessToken);
		}

		Assert.state(map.containsKey("client_id"), "Client id must be present in response from auth server");

		Set<String> scope = new HashSet<String>();
		if (map.containsKey("scope")) {
			@SuppressWarnings("unchecked")
			Collection<String> values = (Collection<String>) map.get("scope");
			scope.addAll(values);
		}
		Set<String> resourceIds = new HashSet<String>();
		if (map.containsKey("resource_ids")) {
			@SuppressWarnings("unchecked")
			Collection<String> values = (Collection<String>) map.get("resource_ids");
			resourceIds.addAll(values);
		}
		Set<GrantedAuthority> clientAuthorities = new HashSet<GrantedAuthority>();
		if (map.containsKey("client_authorities")) {
			@SuppressWarnings("unchecked")
			Collection<String> values = (Collection<String>) map.get("client_authorities");
			clientAuthorities.addAll(getAuthorities(values));
		}
		Set<GrantedAuthority> userAuthorities = new HashSet<GrantedAuthority>();
		if (map.containsKey("user_authorities")) {
			@SuppressWarnings("unchecked")
			Collection<String> values = (Collection<String>) map.get("user_authorities");
			userAuthorities.addAll(getAuthorities(values));
		}
		String remoteClientId = (String) map.get("client_id");
		AuthorizationRequest clientAuthentication = new AuthorizationRequest(remoteClientId, scope, clientAuthorities, resourceIds);
		String username = (String) map.get("user_name");
		Authentication userAuthentication = new UsernamePasswordAuthenticationToken(username, null, userAuthorities);

		return new OAuth2Authentication(clientAuthentication, userAuthentication);
	}

	@Override
	public OAuth2AccessToken readAccessToken(String accessToken) {
		throw new UnsupportedOperationException("Not supported: read access token");
	}

	private Set<GrantedAuthority> getAuthorities(Collection<String> authorities) {
		Set<GrantedAuthority> result = new HashSet<GrantedAuthority>();
		for (String authority : authorities) {
			result.add(new SimpleGrantedAuthority(authority));
		}
		return result;
	}

	private String getAuthorizationHeader(String clientId, String clientSecret) {
		String creds = String.format("%s:%s", clientId, clientSecret);
		try {
			return "Basic " + new String(Base64.encode(creds.getBytes("UTF-8")));
		}
		catch (UnsupportedEncodingException e) {
			throw new IllegalStateException("Could not convert String");
		}
	}

	private Map<String, Object> postForMap(String path, MultiValueMap<String, String> formData, HttpHeaders headers) {
		if (headers.getContentType() == null) {
			headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
		}
		@SuppressWarnings("rawtypes")
		Map map = restTemplate.exchange(path, HttpMethod.POST,
				new HttpEntity<MultiValueMap<String, String>>(formData, headers), Map.class).getBody();
		@SuppressWarnings("unchecked")
		Map<String, Object> result = (Map<String, Object>) map;
		return result;
	}

}
