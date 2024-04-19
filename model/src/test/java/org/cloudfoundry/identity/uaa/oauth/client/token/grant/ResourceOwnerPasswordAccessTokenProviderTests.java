package org.cloudfoundry.identity.uaa.oauth.client.token.grant;

import org.cloudfoundry.identity.uaa.oauth.client.grant.ResourceOwnerPasswordAccessTokenProvider;
import org.cloudfoundry.identity.uaa.oauth.client.resource.OAuth2ProtectedResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.client.resource.ResourceOwnerPasswordResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.token.AccessTokenRequest;
import org.cloudfoundry.identity.uaa.oauth.token.DefaultAccessTokenRequest;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.http.HttpHeaders;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import static org.junit.Assert.assertEquals;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
public class ResourceOwnerPasswordAccessTokenProviderTests {

	@Rule
	public ExpectedException expected = ExpectedException.none();

	private MultiValueMap<String, String> params = new LinkedMultiValueMap<String, String>();

	private ResourceOwnerPasswordAccessTokenProvider provider = new ResourceOwnerPasswordAccessTokenProvider() {
		@Override
		protected OAuth2AccessToken retrieveToken(AccessTokenRequest request, OAuth2ProtectedResourceDetails resource,
				MultiValueMap<String, String> form, HttpHeaders headers) {
			params.putAll(form);
			if (!form.containsKey("username") || form.getFirst("username")==null) {
				throw new IllegalArgumentException();
			}
			// Only the map parts of the AccessTokenRequest are sent as form values
			if (form.containsKey("current_uri") || form.containsKey("currentUri")) {
				throw new IllegalArgumentException();
			}
			return new DefaultOAuth2AccessToken("FOO");
		}
	};

	private ResourceOwnerPasswordResourceDetails resource = new ResourceOwnerPasswordResourceDetails();

	@Test
	public void testGetAccessToken() throws Exception {
		AccessTokenRequest request = new DefaultAccessTokenRequest();
		resource.setAccessTokenUri("http://localhost/oauth/token");
		resource.setUsername("foo");
		resource.setPassword("bar");
		assertEquals("FOO", provider.obtainAccessToken(resource, request).getValue());
	}

	@Test
	public void testGetAccessTokenWithDynamicCredentials() throws Exception {
		AccessTokenRequest request = new DefaultAccessTokenRequest();
		request.set("username", "foo");
		request.set("password", "bar");
		resource.setAccessTokenUri("http://localhost/oauth/token");
		assertEquals("FOO", provider.obtainAccessToken(resource, request).getValue());
	}

	@Test
	public void testCurrentUriNotUsed() throws Exception {
		AccessTokenRequest request = new DefaultAccessTokenRequest();
		request.set("username", "foo");
		request.setCurrentUri("urn:foo:bar");
		resource.setAccessTokenUri("http://localhost/oauth/token");
		assertEquals("FOO", provider.obtainAccessToken(resource, request).getValue());
	}

}
