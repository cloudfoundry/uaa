package org.cloudfoundry.identity.uaa.oauth.provider.authentication;

import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetailsService;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.RequestTokenFactory;
import org.cloudfoundry.identity.uaa.oauth.provider.token.ResourceServerTokenServices;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
public class OAuth2AuthenticationManagerTests {

	private OAuth2AuthenticationManager manager = new OAuth2AuthenticationManager();

	private ResourceServerTokenServices tokenServices = mock(ResourceServerTokenServices.class);

	private Authentication userAuthentication = new UsernamePasswordAuthenticationToken("marissa", "koala");

	private OAuth2Authentication authentication = new OAuth2Authentication(
			RequestTokenFactory.createOAuth2Request("foo", false, Set.of("uaa")), userAuthentication);

	{
		manager.setTokenServices(tokenServices);
	}

	@Test
	public void testDetailsAdded() throws Exception {
		manager.afterPropertiesSet();
		Mockito.when(tokenServices.loadAuthentication("FOO")).thenReturn(authentication);
		PreAuthenticatedAuthenticationToken request = new PreAuthenticatedAuthenticationToken("FOO", "");
		request.setDetails("BAR");
		Authentication result = manager.authenticate(request);
		assertEquals(authentication, result);
		assertEquals("BAR", result.getDetails());
	}

	@Test
	public void testClientDetailsEnhanced() throws Exception {
		authentication.setDetails("DETAILS");
		ClientDetailsService uaaClientDetails = mock(ClientDetailsService.class);
		UaaClientDetails uaaClient = mock(UaaClientDetails.class);
		manager.setResourceId("uaa");
		manager.setClientDetailsService(uaaClientDetails);
		when(uaaClient.getScope()).thenReturn(Set.of("uaa"));
		when(uaaClientDetails.loadClientByClientId(anyString())).thenReturn(uaaClient);
		Mockito.when(tokenServices.loadAuthentication("FOO")).thenReturn(authentication);
		PreAuthenticatedAuthenticationToken request = new PreAuthenticatedAuthenticationToken("FOO", "");
		MockHttpServletRequest servletRequest = new MockHttpServletRequest();
		servletRequest.setAttribute(OAuth2AuthenticationDetails.ACCESS_TOKEN_VALUE, "BAR");
		OAuth2AuthenticationDetails details = new OAuth2AuthenticationDetails(servletRequest);
		request.setDetails(details);
		Authentication result = manager.authenticate(request);
		assertEquals(authentication, result);
		assertEquals("BAR", ((OAuth2AuthenticationDetails) result.getDetails()).getTokenValue());
		assertEquals("DETAILS", ((OAuth2AuthenticationDetails) result.getDetails()).getDecodedDetails());
	}

	@Test
	public void testDetailsEnhanced() throws Exception {
		authentication.setDetails("DETAILS");
		Mockito.when(tokenServices.loadAuthentication("FOO")).thenReturn(authentication);
		PreAuthenticatedAuthenticationToken request = new PreAuthenticatedAuthenticationToken("FOO", "");
		MockHttpServletRequest servletRequest = new MockHttpServletRequest();
		servletRequest.setAttribute(OAuth2AuthenticationDetails.ACCESS_TOKEN_VALUE, "BAR");
		OAuth2AuthenticationDetails details = new OAuth2AuthenticationDetails(servletRequest);
		request.setDetails(details);
		Authentication result = manager.authenticate(request);
		assertEquals(authentication, result);
		assertEquals("BAR", ((OAuth2AuthenticationDetails) result.getDetails()).getTokenValue());
		assertEquals("DETAILS", ((OAuth2AuthenticationDetails) result.getDetails()).getDecodedDetails());
	}

	@Test
	public void testDetailsEnhancedOnce() throws Exception {
		authentication.setDetails("DETAILS");
		Mockito.when(tokenServices.loadAuthentication("FOO")).thenReturn(authentication);
		PreAuthenticatedAuthenticationToken request = new PreAuthenticatedAuthenticationToken("FOO", "");
		MockHttpServletRequest servletRequest = new MockHttpServletRequest();
		servletRequest.setAttribute(OAuth2AuthenticationDetails.ACCESS_TOKEN_VALUE, "BAR");
		OAuth2AuthenticationDetails details = new OAuth2AuthenticationDetails(servletRequest);
		request.setDetails(details);
		Authentication result = manager.authenticate(request);
		// Authenticate the same request again to simulate what happens if the app is caching the result from
		// tokenServices.loadAuthentication():
		result = manager.authenticate(request);
		assertEquals(authentication, result);
		assertEquals("BAR", ((OAuth2AuthenticationDetails) result.getDetails()).getTokenValue());
		assertEquals("DETAILS", ((OAuth2AuthenticationDetails) result.getDetails()).getDecodedDetails());
	}

}
