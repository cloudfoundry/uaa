package org.cloudfoundry.identity.uaa.oauth.provider.refresh;

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
import org.cloudfoundry.identity.uaa.oauth.provider.token.AuthenticationKeyGenerator;
import org.cloudfoundry.identity.uaa.oauth.provider.token.DefaultTokenServices;
import org.cloudfoundry.identity.uaa.oauth.provider.token.InMemoryTokenStore;
import org.cloudfoundry.identity.uaa.oauth.provider.token.TokenStore;
import org.cloudfoundry.identity.uaa.util.AlphanumericRandomValueStringGenerator;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertTrue;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
public class RefreshTokenGranterTests {

	private Authentication validUser = new UsernamePasswordAuthenticationToken("foo", "bar",
			Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));

	private AuthenticationManager authenticationManager = new AuthenticationManager() {
		public Authentication authenticate(Authentication authentication) throws AuthenticationException {
			return validUser;
		}
	};

	private UaaClientDetails client = new UaaClientDetails("foo", "resource", "scope", "refresh_token", "ROLE_USER");

	private TokenStore tokenStore = new InMemoryTokenStore();
	private DefaultTokenServices providerTokenServices = new DefaultTokenServices();

	private ClientDetailsService clientDetailsService = new ClientDetailsService() {
		public ClientDetails loadClientByClientId(String clientId) throws OAuth2Exception {
			return client;
		}
	};

	private OAuth2RequestFactory requestFactory = new DefaultOAuth2RequestFactory(clientDetailsService);

	private OAuth2AccessToken accessToken;

	private TokenRequest validRefreshTokenRequest;

	@Before
	public void setUp() {
		String clientId = "client";
		UaaClientDetails clientDetails = new UaaClientDetails();
		clientDetails.setClientId(clientId);

		((InMemoryTokenStore) tokenStore).setAuthenticationKeyGenerator(new AuthenticationKeyGenerator() {
			String key = new AlphanumericRandomValueStringGenerator(10).generate();
			@Override
			public String extractKey(OAuth2Authentication authentication) {
				return key;
			}
		});
		providerTokenServices.setTokenStore(tokenStore);
		providerTokenServices.setSupportRefreshToken(true);
		providerTokenServices.setAuthenticationManager(authenticationManager);

		// Create access token to refresh
		accessToken = providerTokenServices.createAccessToken(new OAuth2Authentication(requestFactory.createOAuth2Request(client, requestFactory.createTokenRequest(Collections.<String, String>emptyMap(), clientDetails)), validUser));
		validRefreshTokenRequest = createRefreshTokenRequest(accessToken.getRefreshToken().getValue());
	}

	private TokenRequest createRefreshTokenRequest(String refreshToken) {
		Map<String, String> parameters = new HashMap<String, String>();
		parameters.put("grant_type", "refresh_token");
		parameters.put("refresh_token", refreshToken);
		return requestFactory.createTokenRequest(parameters, client);
	}

	@Test
	public void testSunnyDay() {
		RefreshTokenGranter granter = new RefreshTokenGranter(providerTokenServices, clientDetailsService, requestFactory);
		OAuth2AccessToken token = granter.grant("refresh_token", validRefreshTokenRequest);
		OAuth2Authentication authentication = providerTokenServices.loadAuthentication(token.getValue());
		assertTrue(authentication.isAuthenticated());
	}

	@Test(expected = InvalidGrantException.class)
	public void testBadCredentials() {
		RefreshTokenGranter granter = new RefreshTokenGranter(providerTokenServices, clientDetailsService, requestFactory);
		granter.grant("refresh_token", createRefreshTokenRequest(accessToken.getRefreshToken().getValue() + "invalid_token"));
	}

	@Test(expected = InvalidClientException.class)
	public void testGrantTypeNotSupported() {
		RefreshTokenGranter granter = new RefreshTokenGranter(providerTokenServices, clientDetailsService, requestFactory);
		client.setAuthorizedGrantTypes(Collections.singleton("client_credentials"));
		granter.grant("refresh_token", validRefreshTokenRequest);
	}

	@Test(expected = InvalidGrantException.class)
	public void testAccountLocked() {
		providerTokenServices.setAuthenticationManager(new AuthenticationManager() {
			public Authentication authenticate(Authentication authentication) throws AuthenticationException {
				throw new LockedException("test");
			}
		});
		RefreshTokenGranter granter = new RefreshTokenGranter(providerTokenServices, clientDetailsService, requestFactory);
		granter.grant("refresh_token", validRefreshTokenRequest);
	}

	@Test(expected = InvalidGrantException.class)
	public void testUsernameNotFound() {
		providerTokenServices.setAuthenticationManager(new AuthenticationManager() {
			public Authentication authenticate(Authentication authentication) throws AuthenticationException {
				throw new UsernameNotFoundException("test");
			}
		});
		RefreshTokenGranter granter = new RefreshTokenGranter(providerTokenServices, clientDetailsService, requestFactory);
		granter.grant("refresh_token", validRefreshTokenRequest);
	}
}
