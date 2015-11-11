package org.cloudfoundry.identity.uaa.oauth.token.matchers;

import static org.junit.Assert.assertTrue;

import java.util.Map;

import org.cloudfoundry.identity.uaa.oauth.Claims;
import org.hamcrest.Description;
import org.hamcrest.Factory;
import org.hamcrest.Matcher;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

public class OAuth2AccessTokenMatchers extends AbstractOAuth2AccessTokenMatchers<OAuth2AccessToken> {

	private String key;
	
	public OAuth2AccessTokenMatchers(String key, Matcher<?> value) {
		super(value);
		this.key = key;
	}
	
	@Override
	protected boolean matchesSafely(OAuth2AccessToken accessToken) {
        Map<String, Object> claims = getClaims(accessToken);
        return value.matches(claims.get(key)); 
	}

	@Override
	public void describeTo(Description description) {
		description.appendText("Access token attribute " + key + " should return ").appendValue(value);
	}

	@Override
	protected void describeMismatchSafely(OAuth2AccessToken accessToken, Description mismatchDescription) {
		if (accessToken != null) {
	        Map<String, Object> claims = getClaims(accessToken);
			mismatchDescription.appendText(" was ").appendValue(claims.get(key));
		}
	}

	@Factory
	public static Matcher<OAuth2AccessToken> issuerUri(Matcher<Object> issuerUri) {
		return new OAuth2AccessTokenMatchers(Claims.ISS, issuerUri);
	}
	
	@Factory
	public static Matcher<OAuth2AccessToken> clientId(Matcher<Object> clientId) {
		return new OAuth2AccessTokenMatchers(Claims.CLIENT_ID, clientId);
	}
	
	@Factory
	public static Matcher<OAuth2AccessToken> userId(Matcher<Object> userId) {
		return new OAuth2AccessTokenMatchers(Claims.USER_ID, userId);
	}
	
	@Factory
	public static Matcher<OAuth2AccessToken> subject(Matcher<Object> clientId) {
		return new OAuth2AccessTokenMatchers(Claims.SUB, clientId);
	}
	
	@Factory
	public static Matcher<OAuth2AccessToken> cid(Matcher<Object> clientId) {
		return new OAuth2AccessTokenMatchers(Claims.CID, clientId);
	}
	
	@Factory
	public static Matcher<OAuth2AccessToken> scope(Matcher<Object> scopes) {
		return new OAuth2AccessTokenMatchers(Claims.SCOPE, scopes);
	}
	
	@Factory
	public static Matcher<OAuth2AccessToken> audience(Matcher<Object> resourceIds) {
		return new OAuth2AccessTokenMatchers(Claims.AUD, resourceIds);
	}
	
	@Factory
	public static Matcher<OAuth2AccessToken> jwtId(Matcher<String> jti) {
		return new OAuth2AccessTokenMatchers(Claims.JTI, jti);
	}
	
	@Factory
	public static Matcher<OAuth2AccessToken> issuedAt(Matcher<Integer> iat) {
		return new OAuth2AccessTokenMatchers(Claims.IAT, iat);
	}
	
	@Factory
	public static Matcher<OAuth2AccessToken> expiry(Matcher<Integer> expiry) {
		return new OAuth2AccessTokenMatchers(Claims.EXP, expiry);
	}

	@Factory
	public static Matcher<OAuth2AccessToken> username(Matcher<Object> username) {
		return new OAuth2AccessTokenMatchers(Claims.USER_NAME, username);
	}

	@Factory
	public static <T> Matcher<OAuth2AccessToken> zoneId(Matcher<Object> zoneId) {
		return new OAuth2AccessTokenMatchers(Claims.ZONE_ID, zoneId);
	}

	@Factory
	public static <T> Matcher<OAuth2AccessToken> origin(Matcher<Object> origin) {
		return new OAuth2AccessTokenMatchers(Claims.ORIGIN, origin);
	}

	@Factory
	public static <T> Matcher<OAuth2AccessToken> revocationSignature(Matcher<Object> signature) {
		return new OAuth2AccessTokenMatchers(Claims.REVOCATION_SIGNATURE, signature);
	}

	@Factory
	public static <T> Matcher<OAuth2AccessToken> email(Matcher<Object> email) {
		return new OAuth2AccessTokenMatchers(Claims.EMAIL, email);
	}

	@Factory
	public static Matcher<OAuth2AccessToken> validFor(Matcher<?> validFor) {
		return new AbstractOAuth2AccessTokenMatchers<OAuth2AccessToken>() {

			@Override
			protected boolean matchesSafely(OAuth2AccessToken token) {
		        Map<String, Object> claims = getClaims(token);
		        assertTrue(((Integer) claims.get(Claims.IAT)) > 0);
		        assertTrue(((Integer) claims.get(Claims.EXP)) > 0);
		        return validFor.matches(((Integer) claims.get(Claims.EXP)) - ((Integer) claims.get(Claims.IAT))); 
			}
			
			@Override
			public void describeTo(Description description) {
				description.appendText("Refresh token should be valid for ").appendValue(value);
			}

			@Override
			protected void describeMismatchSafely(OAuth2AccessToken accessToken, Description mismatchDescription) {
				if (accessToken != null) {
			        Map<String, Object> claims = getClaims(accessToken);
					mismatchDescription.appendText(" was ").appendValue(((Integer) claims.get(Claims.EXP)) - ((Integer) claims.get(Claims.IAT)));
				}
			}
		};
	}
}
