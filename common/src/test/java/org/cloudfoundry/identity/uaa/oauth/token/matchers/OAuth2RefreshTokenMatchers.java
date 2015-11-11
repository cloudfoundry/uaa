package org.cloudfoundry.identity.uaa.oauth.token.matchers;

import static org.junit.Assert.assertTrue;

import java.util.Map;

import org.cloudfoundry.identity.uaa.oauth.Claims;
import org.hamcrest.Description;
import org.hamcrest.Factory;
import org.hamcrest.Matcher;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;

public class OAuth2RefreshTokenMatchers extends AbstractOAuth2AccessTokenMatchers<OAuth2RefreshToken> {

	private String key;
	
	public OAuth2RefreshTokenMatchers(String key, Matcher<?> value) {
		super(value);
		this.key = key;
	}
	
	@Override
	protected boolean matchesSafely(OAuth2RefreshToken accessToken) {
        Map<String, Object> claims = getClaims(accessToken);
        return value.matches(claims.get(key)); 
	}

	@Override
	public void describeTo(Description description) {
		description.appendText("Refresh token attribute " + key + " should return ").appendValue(value);
	}

	@Override
	protected void describeMismatchSafely(OAuth2RefreshToken accessToken, Description mismatchDescription) {
		if (accessToken != null) {
	        Map<String, Object> claims = getClaims(accessToken);
			mismatchDescription.appendText(" was ").appendValue(claims.get(key));
		}
	}

	@Factory
	public static Matcher<OAuth2RefreshToken> issuerUri(Matcher<Object> issuerUri) {
		return new OAuth2RefreshTokenMatchers(Claims.ISS, issuerUri);
	}
	
	@Factory
	public static Matcher<OAuth2RefreshToken> clientId(Matcher<Object> clientId) {
		return new OAuth2RefreshTokenMatchers(Claims.CLIENT_ID, clientId);
	}
	
	@Factory
	public static Matcher<OAuth2RefreshToken> userId(Matcher<Object> userId) {
		return new OAuth2RefreshTokenMatchers(Claims.USER_ID, userId);
	}
	
	@Factory
	public static Matcher<OAuth2RefreshToken> subject(Matcher<Object> clientId) {
		return new OAuth2RefreshTokenMatchers(Claims.SUB, clientId);
	}
	
	@Factory
	public static Matcher<OAuth2RefreshToken> cid(Matcher<Object> clientId) {
		return new OAuth2RefreshTokenMatchers(Claims.CID, clientId);
	}
	
	@Factory
	public static Matcher<OAuth2RefreshToken> scope(Matcher<Object> scopes) {
		return new OAuth2RefreshTokenMatchers(Claims.SCOPE, scopes);
	}
	
	@Factory
	public static Matcher<OAuth2RefreshToken> audience(Matcher<Object> resourceIds) {
		return new OAuth2RefreshTokenMatchers(Claims.AUD, resourceIds);
	}
	
	@Factory
	public static Matcher<OAuth2RefreshToken> jwtId(Matcher<String> jti) {
		return new OAuth2RefreshTokenMatchers(Claims.JTI, jti);
	}
	
	@Factory
	public static Matcher<OAuth2RefreshToken> issuedAt(Matcher<Integer> iat) {
		return new OAuth2RefreshTokenMatchers(Claims.IAT, iat);
	}
	
	@Factory
	public static Matcher<OAuth2RefreshToken> expiry(Matcher<Integer> expiry) {
		return new OAuth2RefreshTokenMatchers(Claims.EXP, expiry);
	}

	@Factory
	public static Matcher<OAuth2RefreshToken> username(Matcher<Object> username) {
		return new OAuth2RefreshTokenMatchers(Claims.USER_NAME, username);
	}

	@Factory
	public static Matcher<OAuth2RefreshToken> zoneId(Matcher<Object> zoneId) {
		return new OAuth2RefreshTokenMatchers(Claims.ZONE_ID, zoneId);
	}

	@Factory
	public static Matcher<OAuth2RefreshToken> origin(Matcher<Object> origin) {
		return new OAuth2RefreshTokenMatchers(Claims.ORIGIN, origin);
	}

	@Factory
	public static Matcher<OAuth2RefreshToken> revocationSignature(Matcher<Object> signature) {
		return new OAuth2RefreshTokenMatchers(Claims.REVOCATION_SIGNATURE, signature);
	}

	@Factory
	public static Matcher<OAuth2RefreshToken> email(Matcher<Object> email) {
		return new OAuth2RefreshTokenMatchers(Claims.EMAIL, email);
	}

	@Factory
	public static Matcher<OAuth2RefreshToken> validFor(Matcher<?> validFor) {
		return new AbstractOAuth2AccessTokenMatchers<OAuth2RefreshToken>() {

			@Override
			protected boolean matchesSafely(OAuth2RefreshToken token) {
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
			protected void describeMismatchSafely(OAuth2RefreshToken accessToken, Description mismatchDescription) {
				if (accessToken != null) {
			        Map<String, Object> claims = getClaims(accessToken);
					mismatchDescription.appendText(" was ").appendValue(((Integer) claims.get(Claims.EXP)) - ((Integer) claims.get(Claims.IAT)));
				}
			}
		};
	}
}
