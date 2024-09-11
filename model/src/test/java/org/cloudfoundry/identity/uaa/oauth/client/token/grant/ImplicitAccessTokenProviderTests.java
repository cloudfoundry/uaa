package org.cloudfoundry.identity.uaa.oauth.client.token.grant;

import org.cloudfoundry.identity.uaa.oauth.client.grant.ImplicitAccessTokenProvider;
import org.cloudfoundry.identity.uaa.oauth.client.resource.ImplicitResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.client.resource.OAuth2ProtectedResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2RefreshToken;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.token.AccessTokenRequest;
import org.cloudfoundry.identity.uaa.oauth.token.DefaultAccessTokenRequest;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.http.client.MockClientHttpResponse;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.io.IOException;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
public class ImplicitAccessTokenProviderTests {

	@Rule
	public ExpectedException expected = ExpectedException.none();

	private MultiValueMap<String, String> params = new LinkedMultiValueMap<String, String>();

	private ImplicitAccessTokenProvider provider = new ImplicitAccessTokenProvider() {
		@Override
		protected OAuth2AccessToken retrieveToken(AccessTokenRequest request, OAuth2ProtectedResourceDetails resource,
				MultiValueMap<String, String> form, HttpHeaders headers) {
			params.putAll(form);
			return new DefaultOAuth2AccessToken("FOO");
		}
	};

	private ImplicitResourceDetails resource = new ImplicitResourceDetails();

	@Test(expected = IllegalStateException.class)
	public void testRedirectNotSpecified() throws Exception {
		AccessTokenRequest request = new DefaultAccessTokenRequest();
		provider.obtainAccessToken(resource, request);
	}

	@Test
	public void supportsResource() {
		assertTrue(provider.supportsResource(new ImplicitResourceDetails()));
	}

	@Test
	public void supportsRefresh() {
		assertFalse(provider.supportsRefresh(new ImplicitResourceDetails()));
	}

	@Test
	public void refreshAccessToken() {
		assertNull(provider.refreshAccessToken(new ImplicitResourceDetails(), new DefaultOAuth2RefreshToken(""), new DefaultAccessTokenRequest(
				Collections.emptyMap())));
	}

	@Test
	public void testImplicitResponseExtractor() throws IOException {
		assertNull(provider.getResponseExtractor().extractData(new MockClientHttpResponse(new byte[0], 200)));
	}

	@Test
	public void obtainAccessToken() {
		ImplicitResourceDetails details = new ImplicitResourceDetails();
		details.setScope(Set.of("openid").stream().toList());
		assertFalse(details.isClientOnly());
		assertNotNull(provider.obtainAccessToken(details, new DefaultAccessTokenRequest(Map.of("scope", new String[]{ "x" }, "redirect_uri",
				new String[]{ "x" }, "client_id", new String[]{ "x" }))));
	}

	@Test
	public void obtainAccessTokenNoRecdirect() {
		ImplicitResourceDetails details = new ImplicitResourceDetails();
		details.setScope(Set.of("openid").stream().toList());
		assertFalse(details.isClientOnly());
		expected.expect(IllegalStateException.class);
		assertNotNull(provider.obtainAccessToken(details, new DefaultAccessTokenRequest(Map.of("scope", new String[]{ "x" }, "client_id", new String[]{ "x" }))));
	}

	@Test
	public void testGetAccessTokenRequest() throws Exception {
		AccessTokenRequest request = new DefaultAccessTokenRequest();
		resource.setClientId("foo");
		resource.setAccessTokenUri("http://localhost/oauth/authorize");
		resource.setPreEstablishedRedirectUri("https://anywhere.com");
		assertEquals("FOO", provider.obtainAccessToken(resource, request).getValue());
		assertEquals("foo", params.getFirst("client_id"));
		assertEquals("token", params.getFirst("response_type"));
		assertEquals("https://anywhere.com", params.getFirst("redirect_uri"));
	}

}
