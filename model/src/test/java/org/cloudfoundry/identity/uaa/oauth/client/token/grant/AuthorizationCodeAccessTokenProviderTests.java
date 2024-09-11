package org.cloudfoundry.identity.uaa.oauth.client.token.grant;

import org.cloudfoundry.identity.uaa.oauth.client.grant.AuthorizationCodeAccessTokenProvider;
import org.cloudfoundry.identity.uaa.oauth.client.resource.AuthorizationCodeResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.client.resource.OAuth2ProtectedResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.client.resource.UserRedirectRequiredException;
import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2RefreshToken;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidRequestException;
import org.cloudfoundry.identity.uaa.oauth.token.AccessTokenRequest;
import org.cloudfoundry.identity.uaa.oauth.token.DefaultAccessTokenRequest;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.http.HttpHeaders;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.Collections;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
public class AuthorizationCodeAccessTokenProviderTests {

	@Rule
	public ExpectedException expected = ExpectedException.none();

	private MultiValueMap<String, String> params = new LinkedMultiValueMap<String, String>();

	private AuthorizationCodeAccessTokenProvider provider = new AuthorizationCodeAccessTokenProvider() {
		@Override
		protected OAuth2AccessToken retrieveToken(AccessTokenRequest request, OAuth2ProtectedResourceDetails resource,
				MultiValueMap<String, String> form, HttpHeaders headers) {
			params.putAll(form);
			return new DefaultOAuth2AccessToken("FOO");
		}
	};

	private AuthorizationCodeResourceDetails resource = new AuthorizationCodeResourceDetails();

	@Test
	public void supportsResource() {
		assertTrue(provider.supportsResource(new AuthorizationCodeResourceDetails()));
	}

	@Test
	public void getUserApproval() {
		assertNotNull(provider.getUserApprovalSignal(new AuthorizationCodeResourceDetails()));
	}

	@Test
	public void supportsRefresh() {
		assertTrue(provider.supportsRefresh(new AuthorizationCodeResourceDetails()));
	}

	@Test
	public void refreshAccessToken() {
		assertEquals("FOO", provider.refreshAccessToken(new AuthorizationCodeResourceDetails(), new DefaultOAuth2RefreshToken(""), new DefaultAccessTokenRequest(
				Collections.emptyMap())).getValue());
	}

	@Test
	public void testGetAccessToken() throws Exception {
		AccessTokenRequest request = new DefaultAccessTokenRequest();
		request.setAuthorizationCode("foo");
		request.setPreservedState(new Object());
		resource.setAccessTokenUri("http://localhost/oauth/token");
		assertEquals("FOO", provider.obtainAccessToken(resource, request).getValue());
	}

	@Test
	public void testGetCode() throws Exception {
		AccessTokenRequest request = new DefaultAccessTokenRequest();
		request.setAuthorizationCode(null);
		request.setPreservedState(new Object());
		request.setStateKey("key");
		resource.setAccessTokenUri("http://localhost/oauth/token");
		expected.expect(IllegalArgumentException.class);
		assertEquals("FOO", provider.obtainAccessToken(resource, request).getValue());
	}

	@Test
	public void testGetAccessTokenFailsWithNoState() throws Exception {
		AccessTokenRequest request = new DefaultAccessTokenRequest();
		request.setAuthorizationCode("foo");
		resource.setAccessTokenUri("http://localhost/oauth/token");
		expected.expect(InvalidRequestException.class);
		assertEquals("FOO", provider.obtainAccessToken(resource, request).getValue());
	}

	@Test
	public void testRedirectToAuthorizationEndpoint() throws Exception {
		AccessTokenRequest request = new DefaultAccessTokenRequest();
		request.setCurrentUri("/come/back/soon");
		resource.setUserAuthorizationUri("http://localhost/oauth/authorize");
		try {
			provider.obtainAccessToken(resource, request);
			fail("Expected UserRedirectRequiredException");
		}
		catch (UserRedirectRequiredException e) {
			assertEquals("http://localhost/oauth/authorize", e.getRedirectUri());
			assertEquals("/come/back/soon", e.getStateToPreserve());
		}
	}

	// A missing redirect just means the server has to deal with it
	@Test(expected = UserRedirectRequiredException.class)
	public void testRedirectNotSpecified() throws Exception {
		AccessTokenRequest request = new DefaultAccessTokenRequest();
		resource.setUserAuthorizationUri("http://localhost/oauth/authorize");
		provider.obtainAccessToken(resource, request);
	}

	@Test
	public void testGetAccessTokenRequest() throws Exception {
		AccessTokenRequest request = new DefaultAccessTokenRequest();
		request.setAuthorizationCode("foo");
		request.setStateKey("bar");
		request.setPreservedState(new Object());
		resource.setAccessTokenUri("http://localhost/oauth/token");
		resource.setPreEstablishedRedirectUri("https://anywhere.com");
		assertEquals("FOO", provider.obtainAccessToken(resource, request).getValue());
		// System.err.println(params);
		assertEquals("authorization_code", params.getFirst("grant_type"));
		assertEquals("foo", params.getFirst("code"));
		assertEquals("https://anywhere.com", params.getFirst("redirect_uri"));
		// State is not set in token request
		assertEquals(null, params.getFirst("state"));
	}

}
