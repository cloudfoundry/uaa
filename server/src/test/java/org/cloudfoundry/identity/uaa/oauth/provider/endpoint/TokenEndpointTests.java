package org.cloudfoundry.identity.uaa.oauth.provider.endpoint;

import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.oauth.UaaOauth2RequestValidator;
import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidClientException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidGrantException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidRequestException;
import org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetailsService;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Request;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2RequestFactory;
import org.cloudfoundry.identity.uaa.oauth.provider.TokenGranter;
import org.cloudfoundry.identity.uaa.oauth.provider.TokenRequest;
import org.cloudfoundry.identity.uaa.oauth.provider.error.DefaultWebResponseExceptionTranslator;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.web.HttpRequestMethodNotSupportedException;

import java.security.Principal;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
@RunWith(MockitoJUnitRunner.class)
public class TokenEndpointTests {

	@Mock
	private TokenGranter tokenGranter;

	@Mock
	private OAuth2RequestFactory authorizationRequestFactory;

	@Mock
	private ClientDetailsService clientDetailsService;

	private String clientId = "client";
	private UaaClientDetails clientDetails = new UaaClientDetails();

	private TokenEndpoint endpoint;

	private Principal clientAuthentication = new UsernamePasswordAuthenticationToken("client", null,
			Collections.singleton(new SimpleGrantedAuthority("ROLE_CLIENT")));

	private TokenRequest createFromParameters(Map<String, String> parameters) {
		TokenRequest request = new TokenRequest(parameters, parameters.get(OAuth2Utils.CLIENT_ID),
				OAuth2Utils.parseParameterList(parameters.get(OAuth2Utils.SCOPE)),
				parameters.get(OAuth2Utils.GRANT_TYPE));
		return request;
	}

	@Before
	public void init() throws Exception {
		endpoint = new TokenEndpoint();
		endpoint.setTokenGranter(tokenGranter);
		endpoint.setOAuth2RequestFactory(authorizationRequestFactory);
		endpoint.setClientDetailsService(clientDetailsService);
		clientDetails.setScope(Set.of("admin", "read", "write"));
	}

	@Test
	public void testSetterAndGetter() throws Exception {
		endpoint.setProviderExceptionHandler(new DefaultWebResponseExceptionTranslator());
		assertNotNull(endpoint.getExceptionTranslator());
		endpoint.setOAuth2RequestFactory(null);
		endpoint.afterPropertiesSet();
		assertNotNull(endpoint.getOAuth2RequestFactory());
		assertEquals(endpoint.getDefaultOAuth2RequestFactory(), endpoint.getOAuth2RequestFactory());
	}

	@Test
	public void testGetAccessTokenWithNoClientId() throws HttpRequestMethodNotSupportedException {

		HashMap<String, String> parameters = new HashMap<String, String>();
		parameters.put(OAuth2Utils.GRANT_TYPE, "authorization_code");

		OAuth2AccessToken expectedToken = new DefaultOAuth2AccessToken("FOO");
		when(tokenGranter.grant(eq("authorization_code"), any(TokenRequest.class))).thenReturn(
				expectedToken);
		@SuppressWarnings("unchecked")
		Map<String, String> anyMap = any(Map.class);
		when(authorizationRequestFactory.createTokenRequest(anyMap, any())).thenReturn(
				createFromParameters(parameters));

		clientAuthentication = new UsernamePasswordAuthenticationToken(null, null,
				Collections.singleton(new SimpleGrantedAuthority("ROLE_CLIENT")));
		ResponseEntity<OAuth2AccessToken> response = endpoint.postAccessToken(clientAuthentication, parameters);

		assertNotNull(response);
		assertEquals(HttpStatus.OK, response.getStatusCode());
		OAuth2AccessToken body = response.getBody();
		assertEquals(body, expectedToken);
		assertTrue("Wrong body: " + body, body.getTokenType() != null);
	}

	@Test
	public void testGetAccessTokenWithScope() throws HttpRequestMethodNotSupportedException {

		when(clientDetailsService.loadClientByClientId(clientId)).thenReturn(clientDetails);

		HashMap<String, String> parameters = new HashMap<String, String>();
		parameters.put("client_id", clientId);
		parameters.put("scope", "read");
		parameters.put("grant_type", "authorization_code");
		parameters.put("code", "kJAHDFG");

		OAuth2AccessToken expectedToken = new DefaultOAuth2AccessToken("FOO");
		ArgumentCaptor<TokenRequest> captor = ArgumentCaptor.forClass(TokenRequest.class);

		when(tokenGranter.grant(eq("authorization_code"), captor.capture())).thenReturn(expectedToken);
		@SuppressWarnings("unchecked")
		Map<String, String> anyMap = any(Map.class);
		when(authorizationRequestFactory.createTokenRequest(anyMap, eq(clientDetails))).thenReturn(
				createFromParameters(parameters));

		ResponseEntity<OAuth2AccessToken> response = endpoint.postAccessToken(clientAuthentication, parameters);

		assertNotNull(response);
		assertEquals(HttpStatus.OK, response.getStatusCode());
		OAuth2AccessToken body = response.getBody();
		assertEquals(body, expectedToken);
		assertTrue("Wrong body: " + body, body.getTokenType() != null);
		assertTrue("Scope of token request not cleared", captor.getValue().getScope().isEmpty());
	}

    @Test(expected = HttpRequestMethodNotSupportedException.class)
    public void testGetAccessTokenWithUnsupportedRequestParameters() throws HttpRequestMethodNotSupportedException {
        endpoint.getAccessToken(clientAuthentication, new HashMap<String, String>());
    }

	@Test
	public void testGetAccessTokenWithSupportedRequestParametersNotPost() throws HttpRequestMethodNotSupportedException {
		endpoint.setAllowedRequestMethods(new HashSet<HttpMethod>(Arrays.asList(HttpMethod.GET)));
		HashMap<String, String> parameters = new HashMap<String, String>();
		parameters.put("client_id", clientId);
		parameters.put("scope", "read");
		parameters.put("grant_type", "authorization_code");
		parameters.put("code", "kJAHDFG");

		OAuth2AccessToken expectedToken = new DefaultOAuth2AccessToken("FOO");
		when(tokenGranter.grant(eq("authorization_code"), any(TokenRequest.class))).thenReturn(
				expectedToken);
		@SuppressWarnings("unchecked")
		Map<String, String> anyMap = any(Map.class);
		when(authorizationRequestFactory.createTokenRequest(anyMap, any())).thenReturn(
				createFromParameters(parameters));

		ResponseEntity<OAuth2AccessToken> response = endpoint.getAccessToken(clientAuthentication, parameters);
		assertNotNull(response);
		assertEquals(HttpStatus.OK, response.getStatusCode());
		OAuth2AccessToken body = response.getBody();
		assertEquals(body, expectedToken);
		assertTrue("Wrong body: " + body, body.getTokenType() != null);
	}

	@Test(expected = InvalidGrantException.class)
	public void testImplicitGrant() throws HttpRequestMethodNotSupportedException {
		HashMap<String, String> parameters = new HashMap<String, String>();
		parameters.put(OAuth2Utils.GRANT_TYPE, "implicit");
		parameters.put("client_id", clientId);
		parameters.put("scope", "read");
		@SuppressWarnings("unchecked")
		Map<String, String> anyMap = any(Map.class);
		when(authorizationRequestFactory.createTokenRequest(anyMap, eq(clientDetails))).thenReturn(
				createFromParameters(parameters));
		when(clientDetailsService.loadClientByClientId(clientId)).thenReturn(clientDetails);
		endpoint.postAccessToken(clientAuthentication, parameters);
	}

	// gh-1268
	@Test
	public void testGetAccessTokenReturnsHeaderContentTypeJson() throws Exception {
		when(clientDetailsService.loadClientByClientId(clientId)).thenReturn(clientDetails);

		HashMap<String, String> parameters = new HashMap<String, String>();
		parameters.put("client_id", clientId);
		parameters.put("scope", "read");
		parameters.put("grant_type", "authorization_code");
		parameters.put("code", "kJAHDFG");

		OAuth2AccessToken expectedToken = new DefaultOAuth2AccessToken("FOO");

		when(tokenGranter.grant(eq("authorization_code"), any(TokenRequest.class))).thenReturn(expectedToken);

		when(authorizationRequestFactory.createTokenRequest(any(Map.class), eq(clientDetails))).thenReturn(
				createFromParameters(parameters));

		ResponseEntity<OAuth2AccessToken> response = endpoint.postAccessToken(clientAuthentication, parameters);

		assertNotNull(response);
		assertEquals(HttpStatus.OK, response.getStatusCode());
		assertEquals("application/json;charset=UTF-8", response.getHeaders().get("Content-Type").iterator().next());
	}

	@Test(expected = InvalidRequestException.class)
	public void testRefreshTokenGrantTypeWithoutRefreshTokenParameter() throws Exception {
		when(clientDetailsService.loadClientByClientId(clientId)).thenReturn(clientDetails);

		HashMap<String, String> parameters = new HashMap<String, String>();
		parameters.put("client_id", clientId);
		parameters.put("scope", "read");
		parameters.put("grant_type", "refresh_token");

		when(authorizationRequestFactory.createTokenRequest(any(Map.class), eq(clientDetails))).thenReturn(
				createFromParameters(parameters));

		endpoint.postAccessToken(clientAuthentication, parameters);
	}

	@Test
	public void testGetAccessTokenWithRefreshToken() throws Exception {
		when(clientDetailsService.loadClientByClientId(clientId)).thenReturn(clientDetails);

		HashMap<String, String> parameters = new HashMap<String, String>();
		parameters.put("client_id", clientId);
		parameters.put("scope", "read");
		parameters.put("grant_type", "refresh_token");
		parameters.put("refresh_token", "kJAHDFG");

		OAuth2AccessToken expectedToken = new DefaultOAuth2AccessToken("FOO");

		when(tokenGranter.grant(eq("refresh_token"), any(TokenRequest.class))).thenReturn(expectedToken);

		when(authorizationRequestFactory.createTokenRequest(any(Map.class), eq(clientDetails))).thenReturn(
				createFromParameters(parameters));

		ResponseEntity<OAuth2AccessToken> response = endpoint.postAccessToken(clientAuthentication, parameters);

		assertEquals(expectedToken, response.getBody());
	}

	@Test(expected = InsufficientAuthenticationException.class)
	public void testPostAccessException() throws Exception {
		endpoint.postAccessToken(null, Collections.emptyMap());
	}

	@Test(expected = InsufficientAuthenticationException.class)
	public void testGetClientIdException() throws Exception {
		endpoint.getClientId(new UsernamePasswordAuthenticationToken("FOO", "bar"));
	}

	@Test
	public void testGetClientId() throws Exception {
		OAuth2Request oAuth2Request = mock(OAuth2Request.class);
		OAuth2Authentication oAuth2Authentication = mock(OAuth2Authentication.class);
		when(oAuth2Authentication.getOAuth2Request()).thenReturn(oAuth2Request);
		when(oAuth2Authentication.isAuthenticated()).thenReturn(true);
		when(oAuth2Request.getClientId()).thenReturn("FOO");
		assertEquals("FOO", endpoint.getClientId(oAuth2Authentication));
	}

	@Test
	public void testExceptions() throws Exception {
		endpoint.setOAuth2RequestValidator(new UaaOauth2RequestValidator());
		assertEquals("server_error", endpoint.handleException(new Exception("exception")).getBody().getOAuth2ErrorCode());
	}

	@Test
	public void testInvalidClient() throws Exception {
		assertEquals("invalid_client", endpoint.handleException(new InvalidClientException("exception")).getBody().getOAuth2ErrorCode());
	}

	@Test
	public void testInvalidClientException() throws Exception {
		assertEquals("invalid_client", endpoint.handleClientRegistrationException(new InvalidClientException("exception")).getBody().getOAuth2ErrorCode());
	}

	@Test
	public void testNotSupported() throws Exception {
		assertEquals("method_not_allowed", endpoint.handleHttpRequestMethodNotSupportedException(new HttpRequestMethodNotSupportedException("exception")).getBody().getOAuth2ErrorCode());
	}
}
