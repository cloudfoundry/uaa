package org.cloudfoundry.identity.api.oauth;

import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
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
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.ClientToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.OAuth2ProviderTokenServices;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

public class UaaTokenServices implements OAuth2ProviderTokenServices {
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

	public OAuth2AccessToken createAccessToken(OAuth2Authentication authentication) throws AuthenticationException {
		throw new UnsupportedOperationException("Not implemented");
	}

	public OAuth2AccessToken refreshAccessToken(String refreshToken, Set<String> scope) throws AuthenticationException {
		throw new UnsupportedOperationException("Not implemented");
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
		@SuppressWarnings("unchecked")
		Set<String> scope = new HashSet<String>((Collection<String>)map.get("scope"));
		ClientToken clientAuthentication = new ClientToken(clientId, null, clientSecret, scope, null);
		String username = (String) map.get("user_name");
		// TODO: get the user authorities from somewhere
		User user = new User(username, "", Collections.<GrantedAuthority>singleton(new SimpleGrantedAuthority("ROLE_USER")));
		Authentication userAuthentication = new UsernamePasswordAuthenticationToken(user, null, null);
		return new OAuth2Authentication(clientAuthentication, userAuthentication);
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
		Map<String, Object> result = (Map<String, Object>)map;
		return result;
	}

}
