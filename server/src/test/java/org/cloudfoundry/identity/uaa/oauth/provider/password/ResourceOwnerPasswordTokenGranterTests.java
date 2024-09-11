package org.cloudfoundry.identity.uaa.oauth.provider.password;

import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidClientException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidGrantException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.OAuth2Exception;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetailsService;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2RequestFactory;
import org.cloudfoundry.identity.uaa.oauth.provider.TokenRequest;
import org.cloudfoundry.identity.uaa.oauth.provider.request.DefaultOAuth2RequestFactory;
import org.cloudfoundry.identity.uaa.oauth.provider.token.DefaultTokenServices;
import org.cloudfoundry.identity.uaa.oauth.provider.token.InMemoryTokenStore;
import org.junit.Test;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
public class ResourceOwnerPasswordTokenGranterTests {

	private Authentication validUser = new UsernamePasswordAuthenticationToken("foo", "bar",
			Arrays.asList(new SimpleGrantedAuthority("ROLE_USER")));

	private UaaClientDetails client = new UaaClientDetails("foo", "resource", "scope", "password", "ROLE_USER");

	private AuthenticationManager authenticationManager = new AuthenticationManager() {
		public Authentication authenticate(Authentication authentication) throws AuthenticationException {
			return validUser;
		}
	};

	private DefaultTokenServices providerTokenServices = new DefaultTokenServices();

	private ClientDetailsService clientDetailsService = new ClientDetailsService() {
		public ClientDetails loadClientByClientId(String clientId) throws OAuth2Exception {
			return client;
		}
	};

	private OAuth2RequestFactory requestFactory = new DefaultOAuth2RequestFactory(clientDetailsService);

	private TokenRequest tokenRequest;

	public ResourceOwnerPasswordTokenGranterTests() {
		String clientId = "client";
		UaaClientDetails clientDetails = new UaaClientDetails();
		clientDetails.setClientId(clientId);

		providerTokenServices.setTokenStore(new InMemoryTokenStore());
		Map<String, String> parameters = new HashMap<String, String>();
		parameters.put("username", "foo");
		parameters.put("password", "bar");
		parameters.put("client_id", clientId);

		tokenRequest = requestFactory.createTokenRequest(parameters, clientDetails);

	}

	//@Test
	public void testSunnyDay() {
		ResourceOwnerPasswordTokenGranter granter = new ResourceOwnerPasswordTokenGranter(authenticationManager,
				providerTokenServices, clientDetailsService, requestFactory);
		OAuth2AccessToken token = granter.grant("password", tokenRequest);
		OAuth2Authentication authentication = providerTokenServices.loadAuthentication(token.getValue());
		assertTrue(authentication.isAuthenticated());
	}

	//@Test
	public void testPasswordRemoved() {
		ResourceOwnerPasswordTokenGranter granter = new ResourceOwnerPasswordTokenGranter(authenticationManager,
				providerTokenServices, clientDetailsService, requestFactory);
		OAuth2AccessToken token = granter.grant("password", tokenRequest);
		OAuth2Authentication authentication = providerTokenServices.loadAuthentication(token.getValue());
		assertNotNull(authentication.getOAuth2Request().getRequestParameters().get("username"));
		assertNull(authentication.getOAuth2Request().getRequestParameters().get("password"));
	}

	@Test(expected = NullPointerException.class)
	public void testExtraParameters() {
		authenticationManager = new AuthenticationManager() {
			@Override
			public Authentication authenticate(Authentication authentication) throws AuthenticationException {
				if (authentication instanceof UsernamePasswordAuthenticationToken) {
					UsernamePasswordAuthenticationToken user = (UsernamePasswordAuthenticationToken) authentication;
					user = new UsernamePasswordAuthenticationToken(user.getPrincipal(), "N/A",
							AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_USER"));
					@SuppressWarnings("unchecked")
					Map<String,String> details = (Map<String,String>) authentication.getDetails();
					assertNull(details.get("password"));
					return user;
				}
				return authentication;
			}
		};
		ResourceOwnerPasswordTokenGranter granter = new ResourceOwnerPasswordTokenGranter(authenticationManager,
				providerTokenServices, clientDetailsService, requestFactory);
		granter.grant("password", tokenRequest);
	}

	@Test(expected = InvalidGrantException.class)
	public void testBadCredentials() {
		ResourceOwnerPasswordTokenGranter granter = new ResourceOwnerPasswordTokenGranter(new AuthenticationManager() {
			public Authentication authenticate(Authentication authentication) throws AuthenticationException {
				throw new BadCredentialsException("test");
			}
		}, providerTokenServices, clientDetailsService, requestFactory);
		granter.grant("password", tokenRequest);
	}

	@Test(expected = InvalidClientException.class)
	public void testGrantTypeNotSupported() {
		ResourceOwnerPasswordTokenGranter granter = new ResourceOwnerPasswordTokenGranter(authenticationManager,
				providerTokenServices, clientDetailsService, requestFactory);
		client.setAuthorizedGrantTypes(Collections.singleton("client_credentials"));
		granter.grant("password", tokenRequest);
	}

	@Test(expected = InvalidGrantException.class)
	public void testAccountLocked() {
		ResourceOwnerPasswordTokenGranter granter = new ResourceOwnerPasswordTokenGranter(new AuthenticationManager() {
			public Authentication authenticate(Authentication authentication) throws AuthenticationException {
				throw new LockedException("test");
			}
		}, providerTokenServices, clientDetailsService, requestFactory);
		granter.grant("password", tokenRequest);
	}

	@Test(expected = InvalidGrantException.class)
	public void testUnauthenticated() {
		validUser = new UsernamePasswordAuthenticationToken("foo", "bar");
		ResourceOwnerPasswordTokenGranter granter = new ResourceOwnerPasswordTokenGranter(authenticationManager,
				providerTokenServices, clientDetailsService, requestFactory);
		granter.grant("password", tokenRequest);
	}

	@Test(expected = InvalidGrantException.class)
	public void testUsernameNotFound() {
		ResourceOwnerPasswordTokenGranter granter = new ResourceOwnerPasswordTokenGranter(new AuthenticationManager() {
			@Override
			public Authentication authenticate(final Authentication authentication) throws AuthenticationException {
				throw new UsernameNotFoundException("test");
			}
		}, providerTokenServices, clientDetailsService, requestFactory);
		granter.grant("password", tokenRequest);
	}
}
