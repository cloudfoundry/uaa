package org.cloudfoundry.identity.uaa.oauth.client.token.grant;

import org.cloudfoundry.identity.uaa.oauth.client.resource.AuthorizationCodeResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.token.DefaultAccessTokenRequest;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
public class AuthorizationCodeResourceDetailsTests {
	
	private AuthorizationCodeResourceDetails details = new AuthorizationCodeResourceDetails();

	@Test
	public void testGetDefaultRedirectUri() {
		details.setPreEstablishedRedirectUri("https://anywhere.com");
		DefaultAccessTokenRequest request = new DefaultAccessTokenRequest();
		request.setCurrentUri("https://nowhere.com");
		assertEquals("https://nowhere.com", details.getRedirectUri(request));
	}

	@Test
	public void testGetOverrideRedirectUri() {
		details.setPreEstablishedRedirectUri("https://anywhere.com");
		details.setUseCurrentUri(false);
		DefaultAccessTokenRequest request = new DefaultAccessTokenRequest();
		request.setCurrentUri("https://nowhere.com");
		assertEquals("https://anywhere.com", details.getRedirectUri(request));
	}

}
