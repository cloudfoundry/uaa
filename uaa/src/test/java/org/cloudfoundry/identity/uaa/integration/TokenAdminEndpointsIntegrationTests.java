package org.cloudfoundry.identity.uaa.integration;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.Map;

import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.crypto.password.StandardPasswordEncoder;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

/**
 * @author Dave Syer
 */
public class TokenAdminEndpointsIntegrationTests {

	@Rule
	public ServerRunning serverRunning = ServerRunning.isRunning();

	@Rule
	public TestAccountSetup testAccounts = TestAccountSetup.standard();

	@Test
	public void testListTokensByUser() throws Exception {

		OAuth2AccessToken token = getResourceOwnerPasswordAccessToken("read", "token", "scimsecret");

		HttpHeaders headers = getAuthenticatedHeaders(token);
		ResponseEntity<String> result = serverRunning.getForString("/oauth/users/" + testAccounts.getUserName()
				+ "/tokens", headers);
		assertEquals(HttpStatus.OK, result.getStatusCode());
		// System.err.println(result.getBody());
		assertTrue(result.getBody().contains(token.getValue()));
	}

	@Test
	public void testRevokeTokenByUser() throws Exception {

		OAuth2AccessToken token = getResourceOwnerPasswordAccessToken("read write", "token", "scimsecret");
		String hash = new StandardPasswordEncoder().encode(token.getValue());

		HttpHeaders headers = getAuthenticatedHeaders(token);

		HttpEntity<?> request = new HttpEntity<String>(token.getValue(), headers);
		assertEquals(
				HttpStatus.NO_CONTENT,
				serverRunning
						.getRestTemplate()
						.exchange(serverRunning.getUrl("/oauth/users/{user}/tokens/{token}"), HttpMethod.DELETE,
								request, Void.class, testAccounts.getUserName(), hash).getStatusCode());

		ResponseEntity<String> result = serverRunning.getForString("/oauth/users/" + testAccounts.getUserName()
				+ "/tokens", headers);
		assertEquals(HttpStatus.UNAUTHORIZED, result.getStatusCode());
		assertTrue(result.getBody().contains("invalid_token"));

	}

	@Test
	public void testRevokeBogusToken() throws Exception {

		OAuth2AccessToken token = getResourceOwnerPasswordAccessToken("read write", "token", "scimsecret");

		HttpHeaders headers = getAuthenticatedHeaders(token);

		HttpEntity<?> request = new HttpEntity<String>(token.getValue(), headers);
		assertEquals(
				HttpStatus.NOT_FOUND,
				serverRunning
						.getRestTemplate()
						.exchange(serverRunning.getUrl("/oauth/users/{user}/tokens/{token}"), HttpMethod.DELETE,
								request, Void.class, testAccounts.getUserName(), "FOO").getStatusCode());

	}

	@Test
	public void testClientListsTokensByUser() throws Exception {

		OAuth2AccessToken token = getClientCredentialsAccessToken("read", "scim", "scimsecret");

		HttpHeaders headers = getAuthenticatedHeaders(token);
		ResponseEntity<String> result = serverRunning.getForString("/oauth/users/" + testAccounts.getUserName()
				+ "/tokens", headers);
		assertEquals(HttpStatus.OK, result.getStatusCode());
		assertTrue(result.getBody().startsWith("["));
		assertTrue(result.getBody().endsWith("]"));
		assertTrue(result.getBody().length() > 0);
	}

	@Test
	public void testCannotListTokensOfAnotherUser() throws Exception {

		OAuth2AccessToken token = getResourceOwnerPasswordAccessToken("read", "token", "scimsecret");

		HttpHeaders headers = getAuthenticatedHeaders(token);
		assertEquals(HttpStatus.FORBIDDEN, serverRunning.getForString("/oauth/users/foo/tokens", headers)
				.getStatusCode());
	}

	@Test
	public void testListTokensByClient() throws Exception {

		OAuth2AccessToken token = getClientCredentialsAccessToken("read", "scim", "scimsecret");

		HttpHeaders headers = getAuthenticatedHeaders(token);
		ResponseEntity<String> result = serverRunning.getForString("/oauth/clients/scim/tokens", headers);
		assertEquals(HttpStatus.OK, result.getStatusCode());
		assertTrue(result.getBody().contains(token.getValue()));
	}

	@Test
	public void testCannotListTokensOfAnotherClient() throws Exception {

		OAuth2AccessToken token = getClientCredentialsAccessToken("read", "scim", "scimsecret");

		HttpHeaders headers = getAuthenticatedHeaders(token);
		assertEquals(HttpStatus.FORBIDDEN, serverRunning.getForString("/oauth/clients/my/tokens", headers)
				.getStatusCode());
	}

	@Test
	public void testRevokeTokenByClient() throws Exception {

		OAuth2AccessToken token = getClientCredentialsAccessToken("read write", "scim", "scimsecret");
		String hash = new StandardPasswordEncoder().encode(token.getValue());

		HttpHeaders headers = getAuthenticatedHeaders(token);

		HttpEntity<?> request = new HttpEntity<String>(token.getValue(), headers);
		assertEquals(
				HttpStatus.NO_CONTENT,
				serverRunning
						.getRestTemplate()
						.exchange(serverRunning.getUrl("/oauth/clients/scim/tokens/" + hash), HttpMethod.DELETE,
								request, Void.class).getStatusCode());

		ResponseEntity<String> result = serverRunning.getForString("/oauth/clients/scim/tokens/", headers);
		assertEquals(HttpStatus.UNAUTHORIZED, result.getStatusCode());
		assertTrue(result.getBody().contains("invalid_token"));

	}

	@Test
	public void testUserCannotListTokensOfClient() throws Exception {

		OAuth2AccessToken token = getResourceOwnerPasswordAccessToken("read", "token", "scimsecret");

		HttpHeaders headers = getAuthenticatedHeaders(token);
		assertEquals(HttpStatus.FORBIDDEN, serverRunning.getForString("/oauth/clients/scim/tokens", headers)
				.getStatusCode());
	}

	public HttpHeaders getAuthenticatedHeaders(OAuth2AccessToken token) {
		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
		headers.set("Authorization", "Bearer " + token.getValue());
		return headers;
	}

	private OAuth2AccessToken getClientCredentialsAccessToken(String scope, String clientId, String clientSecret)
			throws Exception {

		MultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
		formData.add("grant_type", "client_credentials");
		formData.add("client_id", clientId);
		formData.add("scope", scope);
		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
		headers.set("Authorization",
				"Basic " + new String(Base64.encode(String.format("%s:%s", clientId, clientSecret).getBytes())));

		@SuppressWarnings("rawtypes")
		ResponseEntity<Map> response = serverRunning.postForMap("/oauth/token", formData, headers);
		assertEquals(HttpStatus.OK, response.getStatusCode());

		@SuppressWarnings("unchecked")
		OAuth2AccessToken accessToken = OAuth2AccessToken.valueOf(response.getBody());
		return accessToken;

	}

	private OAuth2AccessToken getResourceOwnerPasswordAccessToken(String scope, String clientId, String clientSecret)
			throws Exception {

		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
		headers.set("Authorization",
				"Basic " + new String(Base64.encode(String.format("%s:%s", clientId, clientSecret).getBytes())));

		MultiValueMap<String, String> formData = getTokenFormData(scope, clientId);

		@SuppressWarnings("rawtypes")
		ResponseEntity<Map> response = serverRunning.postForMap("/oauth/token", formData, headers);
		assertEquals(HttpStatus.OK, response.getStatusCode());

		@SuppressWarnings("unchecked")
		OAuth2AccessToken accessToken = OAuth2AccessToken.valueOf(response.getBody());
		return accessToken;
	}

	private MultiValueMap<String, String> getTokenFormData(String scope, String clientId) {
		MultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
		formData.add("grant_type", "password");
		if (clientId != null) {
			formData.add("client_id", clientId);
		}
		formData.add("scope", scope);
		formData.add("username", testAccounts.getUserName());
		formData.add("password", testAccounts.getPassword());
		return formData;
	}

}
