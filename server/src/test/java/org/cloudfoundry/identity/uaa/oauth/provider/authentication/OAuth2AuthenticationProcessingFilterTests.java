package org.cloudfoundry.identity.uaa.oauth.provider.authentication;

import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidTokenException;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.RequestTokenFactory;
import org.cloudfoundry.identity.uaa.oauth.provider.error.OAuth2AuthenticationEntryPoint;
import org.junit.After;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;

import jakarta.servlet.FilterChain;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
public class OAuth2AuthenticationProcessingFilterTests {

	private OAuth2AuthenticationProcessingFilter filter = new OAuth2AuthenticationProcessingFilter();

	private MockHttpServletRequest request = new MockHttpServletRequest();

	private MockHttpServletResponse response = new MockHttpServletResponse();

	private Authentication userAuthentication = new UsernamePasswordAuthenticationToken("marissa", "koala");

	private OAuth2Authentication authentication = new OAuth2Authentication(RequestTokenFactory.createOAuth2Request(
			null, "foo", null, false, null, null, null, null, null), userAuthentication);

	private FilterChain chain = Mockito.mock(FilterChain.class);

	{
		filter.setAuthenticationManager(new AuthenticationManager() {

			public Authentication authenticate(Authentication request) throws AuthenticationException {
				if ("BAD".equals(request.getPrincipal())) {
					throw new InvalidTokenException("Invalid token");
				}
				authentication.setDetails(request.getDetails());
				return authentication;
			}
		});
	}

	@After
	public void clear() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void testDetailsAdded() throws Exception {
		request.addHeader("Authorization", "Bearer FOO");
		filter.doFilter(request, null, chain);
		assertNotNull(request.getAttribute(OAuth2AuthenticationDetails.ACCESS_TOKEN_VALUE));
		assertEquals("Bearer", request.getAttribute(OAuth2AuthenticationDetails.ACCESS_TOKEN_TYPE));
		Authentication result = SecurityContextHolder.getContext().getAuthentication();
		assertEquals(authentication, result);
		assertNotNull(result.getDetails());
	}

	@Test
	public void testDetailsSetter() throws Exception {
		filter.setAuthenticationEntryPoint(new OAuth2AuthenticationEntryPoint());
		filter.setAuthenticationDetailsSource(new OAuth2AuthenticationDetailsSource());
		filter.setTokenExtractor(new BearerTokenExtractor());
		filter.afterPropertiesSet();
		assertNotNull(filter.getClass());
	}

	@Test
	public void testDetailsAddedWithForm() throws Exception {
		request.addParameter("access_token", "FOO");
		filter.doFilter(request, null, chain);
		assertNotNull(request.getAttribute(OAuth2AuthenticationDetails.ACCESS_TOKEN_VALUE));
		assertEquals(OAuth2AccessToken.BEARER_TYPE, request.getAttribute(OAuth2AuthenticationDetails.ACCESS_TOKEN_TYPE));
		Authentication result = SecurityContextHolder.getContext().getAuthentication();
		assertEquals(authentication, result);
		assertNotNull(result.getDetails());
	}

	@Test
	public void testStateless() throws Exception {
		SecurityContextHolder.getContext().setAuthentication(
				new UsernamePasswordAuthenticationToken("FOO", "foo", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS")));
		filter.doFilter(request, null, chain);
		assertNull(SecurityContextHolder.getContext().getAuthentication());
	}

	@Test
	public void testStatelessPreservesAnonymous() throws Exception {
		SecurityContextHolder.getContext().setAuthentication(
				new AnonymousAuthenticationToken("FOO", "foo", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS")));
		filter.doFilter(request, null, chain);
		assertNotNull(SecurityContextHolder.getContext().getAuthentication());
	}
	
	@Test
	public void testStateful() throws Exception {
		filter.setStateless(false);
		SecurityContextHolder.getContext().setAuthentication(
				new UsernamePasswordAuthenticationToken("FOO", "foo", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS")));
		filter.doFilter(request, null, chain);
		assertNotNull(SecurityContextHolder.getContext().getAuthentication());
	}

	@Test
	public void testNoEventsPublishedWithNoToken() throws Exception {
		AuthenticationEventPublisher eventPublisher = Mockito.mock(AuthenticationEventPublisher.class);
		filter.setAuthenticationEventPublisher(eventPublisher);
		filter.doFilter(request, null, chain);
		Mockito.verify(eventPublisher, Mockito.never()).publishAuthenticationFailure(Mockito.any(AuthenticationException.class), Mockito.any(Authentication.class));
		Mockito.verify(eventPublisher, Mockito.never()).publishAuthenticationSuccess(Mockito.any(Authentication.class));
	}

	@Test
	public void testSuccessEventsPublishedWithToken() throws Exception {
		request.addHeader("Authorization", "Bearer FOO");
		AuthenticationEventPublisher eventPublisher = Mockito.mock(AuthenticationEventPublisher.class);
		filter.setAuthenticationEventPublisher(eventPublisher);
		filter.doFilter(request, null, chain);
		Mockito.verify(eventPublisher, Mockito.never()).publishAuthenticationFailure(Mockito.any(AuthenticationException.class), Mockito.any(Authentication.class));
		Mockito.verify(eventPublisher).publishAuthenticationSuccess(Mockito.any(Authentication.class));
	}

	@Test
	public void testFailureEventsPublishedWithBadToken() throws Exception {
		request.addHeader("Authorization", "Bearer BAD");
		filter.doFilter(request, response, chain);
		AuthenticationEventPublisher eventPublisher = Mockito.mock(AuthenticationEventPublisher.class);
		filter.setAuthenticationEventPublisher(eventPublisher);
		filter.doFilter(request, response, chain);
		Mockito.verify(eventPublisher).publishAuthenticationFailure(Mockito.any(AuthenticationException.class), Mockito.any(Authentication.class));
		Mockito.verify(eventPublisher, Mockito.never()).publishAuthenticationSuccess(Mockito.any(Authentication.class));
	}

}
