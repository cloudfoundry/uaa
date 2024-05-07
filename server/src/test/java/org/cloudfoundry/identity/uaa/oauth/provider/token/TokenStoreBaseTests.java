package org.cloudfoundry.identity.uaa.oauth.provider.token;

import org.cloudfoundry.identity.uaa.oauth.common.DefaultExpiringOAuth2RefreshToken;
import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2RefreshToken;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2RefreshToken;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Request;
import org.cloudfoundry.identity.uaa.oauth.provider.RequestTokenFactory;
import org.junit.Test;
import org.springframework.security.authentication.AbstractAuthenticationToken;

import java.util.Collection;
import java.util.Date;
import java.util.UUID;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
public abstract class TokenStoreBaseTests {

	public abstract TokenStore getTokenStore();

	@Test
	public void testReadingAuthenticationForTokenThatDoesNotExist() {
		assertNull(getTokenStore().readAuthentication("tokenThatDoesNotExist"));
	}

	@Test
	public void testStoreAccessToken() {
		OAuth2Authentication expectedAuthentication = new OAuth2Authentication(RequestTokenFactory.createOAuth2Request("id", false), new TestAuthentication("test2", false));
		OAuth2AccessToken expectedOAuth2AccessToken = new DefaultOAuth2AccessToken("testToken");
		getTokenStore().storeAccessToken(expectedOAuth2AccessToken, expectedAuthentication);

		OAuth2AccessToken actualOAuth2AccessToken = getTokenStore().readAccessToken("testToken");
		assertEquals(expectedOAuth2AccessToken, actualOAuth2AccessToken);
		assertEquals(expectedAuthentication, getTokenStore().readAuthentication(expectedOAuth2AccessToken));
		getTokenStore().removeAccessToken(expectedOAuth2AccessToken);
		getTokenStore().removeAccessTokenUsingRefreshToken(new DefaultOAuth2RefreshToken("testToken"));
		assertNull(getTokenStore().readAccessToken("testToken"));
		assertNull(getTokenStore().readAuthentication(expectedOAuth2AccessToken.getValue()));
	}

	@Test
	public void testStoreAccessTokenTwice() {
		OAuth2Authentication expectedAuthentication = new OAuth2Authentication(
				RequestTokenFactory.createOAuth2Request( "id", false), new TestAuthentication("test2", false));
		OAuth2AccessToken expectedOAuth2AccessToken = new DefaultOAuth2AccessToken("testToken");
		getTokenStore().storeAccessToken(expectedOAuth2AccessToken, expectedAuthentication);
		getTokenStore().storeAccessToken(expectedOAuth2AccessToken, expectedAuthentication);

		OAuth2AccessToken actualOAuth2AccessToken = getTokenStore().readAccessToken("testToken");
		assertEquals(expectedOAuth2AccessToken, actualOAuth2AccessToken);
		assertEquals(expectedAuthentication, getTokenStore().readAuthentication(expectedOAuth2AccessToken));
		getTokenStore().removeAccessToken(expectedOAuth2AccessToken);
		assertNull(getTokenStore().readAccessToken("testToken"));
		assertNull(getTokenStore().readAuthentication(expectedOAuth2AccessToken.getValue()));
	}

	@Test
	public void testRetrieveAccessToken() {
		//Test approved request
		OAuth2Request storedOAuth2Request = RequestTokenFactory.createOAuth2Request("id", true);
		OAuth2Authentication authentication = new OAuth2Authentication(storedOAuth2Request, new TestAuthentication("test2", true));
		DefaultOAuth2AccessToken expectedOAuth2AccessToken = new DefaultOAuth2AccessToken("testToken");
		expectedOAuth2AccessToken.setExpiration(new Date(Long.MAX_VALUE-1));
		getTokenStore().storeAccessToken(expectedOAuth2AccessToken, authentication);

		//Test unapproved request
		storedOAuth2Request = RequestTokenFactory.createOAuth2Request("id", false);
		authentication = new OAuth2Authentication(storedOAuth2Request, new TestAuthentication("test2", true));
		OAuth2AccessToken actualOAuth2AccessToken = getTokenStore().getAccessToken(authentication);
		assertEquals(expectedOAuth2AccessToken, actualOAuth2AccessToken);
		assertEquals(authentication.getUserAuthentication(), getTokenStore().readAuthentication(expectedOAuth2AccessToken.getValue()).getUserAuthentication());
		// The authorizationRequest does not match because it is unapproved, but the token was granted to an approved request
		assertFalse(storedOAuth2Request.equals(getTokenStore().readAuthentication(expectedOAuth2AccessToken.getValue()).getOAuth2Request()));
		actualOAuth2AccessToken = getTokenStore().getAccessToken(authentication);
		assertEquals(expectedOAuth2AccessToken, actualOAuth2AccessToken);
		getTokenStore().removeAccessToken(expectedOAuth2AccessToken);
		assertNull(getTokenStore().readAccessToken("testToken"));
		assertNull(getTokenStore().readAuthentication(expectedOAuth2AccessToken.getValue()));
		assertNull(getTokenStore().getAccessToken(authentication));
	}

	@Test
	public void testFindAccessTokensByClientIdAndUserName() {
		String clientId = "id" + UUID.randomUUID();
		String name = "test2" + UUID.randomUUID();
		OAuth2Authentication expectedAuthentication = new OAuth2Authentication(RequestTokenFactory.createOAuth2Request(clientId, false), new TestAuthentication(name, false));
		OAuth2AccessToken expectedOAuth2AccessToken = new DefaultOAuth2AccessToken("testToken");
		getTokenStore().storeAccessToken(expectedOAuth2AccessToken, expectedAuthentication);

		Collection<OAuth2AccessToken> actualOAuth2AccessTokens = getTokenStore().findTokensByClientIdAndUserName(clientId, name);
		assertEquals(1, actualOAuth2AccessTokens.size());
	}

	@Test
	public void testFindAccessTokensByClientId() {
		String clientId = "id" + UUID.randomUUID();
		OAuth2Authentication expectedAuthentication = new OAuth2Authentication(RequestTokenFactory.createOAuth2Request(clientId, false), new TestAuthentication("test2", false));
		OAuth2AccessToken expectedOAuth2AccessToken = new DefaultOAuth2AccessToken("testToken");
		getTokenStore().storeAccessToken(expectedOAuth2AccessToken, expectedAuthentication);

		Collection<OAuth2AccessToken> actualOAuth2AccessTokens = getTokenStore().findTokensByClientId(clientId);
		assertEquals(1, actualOAuth2AccessTokens.size());
	}

	@Test
	public void testReadingAccessTokenForTokenThatDoesNotExist() {
		assertNull(getTokenStore().readAccessToken("tokenThatDoesNotExist"));
	}

	@Test
	public void testRefreshTokenIsNotStoredDuringAccessToken() {
		OAuth2Authentication expectedAuthentication = new OAuth2Authentication(RequestTokenFactory.createOAuth2Request("id", false), new TestAuthentication("test2", false));
		DefaultOAuth2AccessToken expectedOAuth2AccessToken = new DefaultOAuth2AccessToken("testToken");
		expectedOAuth2AccessToken.setRefreshToken(new DefaultOAuth2RefreshToken("refreshToken"));
		getTokenStore().storeAccessToken(expectedOAuth2AccessToken, expectedAuthentication);

		OAuth2AccessToken actualOAuth2AccessToken = getTokenStore().readAccessToken("testToken");
		assertNotNull(actualOAuth2AccessToken.getRefreshToken());
		
		assertNull(getTokenStore().readRefreshToken("refreshToken"));
	}

	@Test
	/**
	 * NB: This used to test expiring refresh tokens. That test has been moved to sub-classes since not all stores support the functionality
	 */
	public void testStoreRefreshToken() {
		String refreshToken = "testToken" + UUID.randomUUID();
		DefaultOAuth2RefreshToken expectedRefreshToken = new DefaultOAuth2RefreshToken(refreshToken);
		OAuth2Authentication expectedAuthentication = new OAuth2Authentication(RequestTokenFactory.createOAuth2Request("id", false), new TestAuthentication("test2", false));
		getTokenStore().storeRefreshToken(expectedRefreshToken, expectedAuthentication);

		OAuth2RefreshToken actualExpiringRefreshToken = getTokenStore().readRefreshToken(refreshToken);
		assertEquals(expectedRefreshToken, actualExpiringRefreshToken);
		assertEquals(expectedAuthentication, getTokenStore().readAuthenticationForRefreshToken(expectedRefreshToken));
		getTokenStore().removeRefreshToken(expectedRefreshToken);
		assertNull(getTokenStore().readRefreshToken(refreshToken));
		assertNull(getTokenStore().readAuthentication(expectedRefreshToken.getValue()));
	}

	@Test
	public void testReadingRefreshTokenForTokenThatDoesNotExist() {
		assertNull(getTokenStore().readRefreshToken("tokenThatDoesNotExist"));
	}

	@Test
	public void testGetAccessTokenForDeletedUser() throws Exception {
		//Test approved request
		OAuth2Request storedOAuth2Request = RequestTokenFactory.createOAuth2Request("id", true);
		OAuth2Authentication expectedAuthentication = new OAuth2Authentication(storedOAuth2Request, new TestAuthentication("test", true));
		OAuth2AccessToken expectedOAuth2AccessToken = new DefaultOAuth2AccessToken("testToken");
		getTokenStore().storeAccessToken(expectedOAuth2AccessToken, expectedAuthentication);
		assertEquals(expectedOAuth2AccessToken, getTokenStore().getAccessToken(expectedAuthentication));
		assertEquals(expectedAuthentication, getTokenStore().readAuthentication(expectedOAuth2AccessToken.getValue()));
		
		//Test unapproved request
		storedOAuth2Request = RequestTokenFactory.createOAuth2Request("id", false);
		OAuth2Authentication anotherAuthentication = new OAuth2Authentication(storedOAuth2Request, new TestAuthentication("test", true));
		assertEquals(expectedOAuth2AccessToken, getTokenStore().getAccessToken(anotherAuthentication));
		// The generated key for the authentication is the same as before, but the two auths are not equal. This could
		// happen if there are 2 users in a system with the same username, or (more likely), if a user account was
		// deleted and re-created.
		assertEquals(anotherAuthentication.getUserAuthentication(), getTokenStore().readAuthentication(expectedOAuth2AccessToken.getValue()).getUserAuthentication());
		// The authorizationRequest does not match because it is unapproved, but the token was granted to an approved request
		assertFalse(storedOAuth2Request.equals(getTokenStore().readAuthentication(expectedOAuth2AccessToken.getValue()).getOAuth2Request()));
	}

	@Test
	public void testRemoveRefreshToken() {
		OAuth2RefreshToken expectedExpiringRefreshToken = new DefaultExpiringOAuth2RefreshToken("testToken",
				new Date());
		OAuth2Authentication expectedAuthentication = new OAuth2Authentication(RequestTokenFactory.createOAuth2Request("id", false), new TestAuthentication("test2", false));
		getTokenStore().storeRefreshToken(expectedExpiringRefreshToken, expectedAuthentication);
		getTokenStore().removeRefreshToken(expectedExpiringRefreshToken);
		
		assertNull(getTokenStore().readRefreshToken("testToken"));
	}

	@Test
	public void testRemovedTokenCannotBeFoundByUsername() {
		OAuth2AccessToken token = new DefaultOAuth2AccessToken("testToken");
		OAuth2Authentication expectedAuthentication = new OAuth2Authentication(RequestTokenFactory.createOAuth2Request(
				"id", false), new TestAuthentication("test2", false));
		getTokenStore().storeAccessToken(token, expectedAuthentication);
		getTokenStore().removeAccessToken(token);
		Collection<OAuth2AccessToken> tokens = getTokenStore().findTokensByClientIdAndUserName("id", "test2");
		assertFalse(tokens.contains(token));
		assertTrue(tokens.isEmpty());
	}

	protected static class TestAuthentication extends AbstractAuthenticationToken {

		private static final long serialVersionUID = 1L;
		private String principal;

		public TestAuthentication(String name, boolean authenticated) {
			super(null);
			setAuthenticated(authenticated);
			this.principal = name;
		}

		public Object getCredentials() {
			return null;
		}

		public Object getPrincipal() {
			return this.principal;
		}
	}

}
