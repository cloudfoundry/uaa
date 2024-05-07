package org.cloudfoundry.identity.uaa.oauth.provider.token;

import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.ExpiringOAuth2RefreshToken;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2RefreshToken;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidTokenException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.OAuth2Exception;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetailsService;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.RequestTokenFactory;
import org.cloudfoundry.identity.uaa.oauth.provider.TokenRequest;
import org.cloudfoundry.identity.uaa.util.AlphanumericRandomValueStringGenerator;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Arrays;
import java.util.Collections;
import java.util.Date;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
public class DefaultTokenServicesWithInMemoryTests extends AbstractPersistentDefaultTokenServicesTests {

	private InMemoryTokenStore tokenStore;

	@Rule
	public ExpectedException expected = ExpectedException.none();

	@Test
	public void testExpiredToken() throws Exception {
		OAuth2Authentication expectedAuthentication = new OAuth2Authentication(RequestTokenFactory.createOAuth2Request(
				"id", false, Collections.singleton("read")), new TestAuthentication("test2", false));
		DefaultOAuth2AccessToken firstAccessToken = (DefaultOAuth2AccessToken) getTokenServices().createAccessToken(
				expectedAuthentication);
		// Make it expire (and rely on mutable state in volatile token store)
		firstAccessToken.setExpiration(new Date(System.currentTimeMillis() - 1000));
		expected.expect(InvalidTokenException.class);
		expected.expectMessage("expired");
		getTokenServices().loadAuthentication(firstAccessToken.getValue());
	}

	@Test
	public void testExpiredRefreshToken() throws Exception {
		OAuth2Authentication expectedAuthentication = new OAuth2Authentication(RequestTokenFactory.createOAuth2Request(
				"id", false, Collections.singleton("read")), new TestAuthentication("test2", false));
		DefaultOAuth2AccessToken firstAccessToken = (DefaultOAuth2AccessToken) getTokenServices().createAccessToken(
				expectedAuthentication);
		assertNotNull(firstAccessToken.getRefreshToken());
		// Make it expire (and rely on mutable state in volatile token store)
		ReflectionTestUtils.setField(firstAccessToken.getRefreshToken(), "expiration",
				new Date(System.currentTimeMillis() - 1000));
		firstAccessToken.setExpiration(new Date(System.currentTimeMillis() - 1000));
		expected.expect(InvalidTokenException.class);
		expected.expectMessage("refresh token (expired)");
		TokenRequest tokenRequest = new TokenRequest(Collections.singletonMap("client_id", "id"), "id", null, null);
		getTokenServices().refreshAccessToken(firstAccessToken.getRefreshToken().getValue(), tokenRequest);
	}

	@Test
	public void testRefreshTokenWithUnauthenticatedUser() throws Exception {
		OAuth2Authentication expectedAuthentication = new OAuth2Authentication(RequestTokenFactory.createOAuth2Request(
				"id", false, Collections.singleton("read")), new TestAuthentication("test2", false));
		getTokenServices().setAuthenticationManager(new AuthenticationManager() {
			
			@Override
			public Authentication authenticate(Authentication authentication) throws AuthenticationException {
				throw new AccountExpiredException("Not valid");
			}
		});
		DefaultOAuth2AccessToken firstAccessToken = (DefaultOAuth2AccessToken) getTokenServices().createAccessToken(
				expectedAuthentication);
		assertNotNull(firstAccessToken.getRefreshToken());
		expected.expect(AccountExpiredException.class);
		TokenRequest tokenRequest = new TokenRequest(Collections.singletonMap("client_id", "id"), "id", null, null);
		getTokenServices().refreshAccessToken(firstAccessToken.getRefreshToken().getValue(), tokenRequest);
	}

	@Test
	public void testExpiredRefreshTokenIsRenewedWithNewAccessToken() throws Exception {
		OAuth2Authentication expectedAuthentication = new OAuth2Authentication(RequestTokenFactory.createOAuth2Request(
				"id", false, Collections.singleton("read")), new TestAuthentication("test2", false));
		DefaultOAuth2AccessToken firstAccessToken = (DefaultOAuth2AccessToken) getTokenServices().createAccessToken(
				expectedAuthentication);
		assertNotNull(firstAccessToken.getRefreshToken());
		// Make it expire (and rely on mutable state in volatile token store)
		ReflectionTestUtils.setField(firstAccessToken.getRefreshToken(), "expiration",
				new Date(System.currentTimeMillis() - 1000));
		firstAccessToken.setExpiration(new Date(System.currentTimeMillis() - 1000));
		DefaultOAuth2AccessToken secondAccessToken = (DefaultOAuth2AccessToken) getTokenServices().createAccessToken(
				expectedAuthentication);
		ExpiringOAuth2RefreshToken refreshToken = (ExpiringOAuth2RefreshToken) secondAccessToken.getRefreshToken();
		assertNotNull(refreshToken);
		assertTrue(refreshToken.getExpiration().getTime() > System.currentTimeMillis());
	}

	@Test
	public void testDifferentRefreshTokenMaintainsState() throws Exception {
		// create access token
		getTokenServices().setAccessTokenValiditySeconds(1);
		getTokenServices().setClientDetailsService(new ClientDetailsService() {
			public ClientDetails loadClientByClientId(String clientId) throws OAuth2Exception {
				UaaClientDetails client = new UaaClientDetails();
				client.setAccessTokenValiditySeconds(1);
				client.setAuthorizedGrantTypes(Arrays.asList("authorization_code", "refresh_token"));
				return client;
			}
		});
		OAuth2Authentication expectedAuthentication = new OAuth2Authentication(RequestTokenFactory.createOAuth2Request(
				"id", false, Collections.singleton("read")), new TestAuthentication("test2", false));
		DefaultOAuth2AccessToken firstAccessToken = (DefaultOAuth2AccessToken) getTokenServices().createAccessToken(
				expectedAuthentication);
		OAuth2RefreshToken expectedExpiringRefreshToken = firstAccessToken.getRefreshToken();
		// Make it expire (and rely on mutable state in volatile token store)
		firstAccessToken.setExpiration(new Date(System.currentTimeMillis() - 1000));
		// create another access token
		OAuth2AccessToken secondAccessToken = getTokenServices().createAccessToken(expectedAuthentication);
		assertFalse("The new access token should be different",
				firstAccessToken.getValue().equals(secondAccessToken.getValue()));
		assertEquals("The new access token should have the same refresh token",
				expectedExpiringRefreshToken.getValue(), secondAccessToken.getRefreshToken().getValue());
		// refresh access token with refresh token

		TokenRequest tokenRequest = new TokenRequest(Collections.singletonMap("client_id", "id"), "id",
				Collections.singleton("read"), null);
		getTokenServices().refreshAccessToken(expectedExpiringRefreshToken.getValue(), tokenRequest);
		assertEquals(1, getAccessTokenCount());
	}

	@Test
	public void testNoRefreshTokenIfNotAuthorized() throws Exception {
		// create access token
		getTokenServices().setAccessTokenValiditySeconds(1);
		getTokenServices().setClientDetailsService(new ClientDetailsService() {
			public ClientDetails loadClientByClientId(String clientId) throws OAuth2Exception {
				UaaClientDetails client = new UaaClientDetails();
				client.setAccessTokenValiditySeconds(1);
				client.setAuthorizedGrantTypes(Arrays.asList("authorization_code"));
				return client;
			}
		});
		OAuth2Authentication expectedAuthentication = new OAuth2Authentication(RequestTokenFactory.createOAuth2Request(
				"id", false, Collections.singleton("read")), new TestAuthentication("test2", false));
		DefaultOAuth2AccessToken token = (DefaultOAuth2AccessToken) getTokenServices().createAccessToken(
				expectedAuthentication);
		assertNull(token.getRefreshToken());
	}

	@Override
	protected TokenStore createTokenStore() {
		tokenStore = new InMemoryTokenStore();
		tokenStore.setAuthenticationKeyGenerator(new AuthenticationKeyGenerator() {
			String key = new AlphanumericRandomValueStringGenerator(10).generate();
			@Override
			public String extractKey(OAuth2Authentication authentication) {
				return key;
			}
		});
		return tokenStore;
	}

	@Override
	protected int getAccessTokenCount() {
		return tokenStore.getAccessTokenCount();
	}

	@Override
	protected int getRefreshTokenCount() {
		return tokenStore.getRefreshTokenCount();
	}

}
