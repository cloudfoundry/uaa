package org.cloudfoundry.identity.uaa.oauth.token.matchers;

import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.hamcrest.Description;
import org.hamcrest.Factory;
import org.hamcrest.Matcher;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

import java.util.Map;

import static org.junit.Assert.assertTrue;

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
        return new OAuth2AccessTokenMatchers(ClaimConstants.ISS, issuerUri);
    }

    @Factory
    public static Matcher<OAuth2AccessToken> clientId(Matcher<Object> clientId) {
        return new OAuth2AccessTokenMatchers(ClaimConstants.CLIENT_ID, clientId);
    }

    @Factory
    public static Matcher<OAuth2AccessToken> userId(Matcher<Object> userId) {
        return new OAuth2AccessTokenMatchers(ClaimConstants.USER_ID, userId);
    }

    @Factory
    public static Matcher<OAuth2AccessToken> subject(Matcher<Object> clientId) {
        return new OAuth2AccessTokenMatchers(ClaimConstants.SUB, clientId);
    }

    @Factory
    public static Matcher<OAuth2AccessToken> cid(Matcher<Object> clientId) {
        return new OAuth2AccessTokenMatchers(ClaimConstants.CID, clientId);
    }

    @Factory
    public static Matcher<OAuth2AccessToken> scope(Matcher<Object> scopes) {
        return new OAuth2AccessTokenMatchers(ClaimConstants.SCOPE, scopes);
    }

    @Factory
    public static Matcher<OAuth2AccessToken> audience(Matcher<Object> resourceIds) {
        return new OAuth2AccessTokenMatchers(ClaimConstants.AUD, resourceIds);
    }

    @Factory
    public static Matcher<OAuth2AccessToken> jwtId(Matcher<String> jti) {
        return new OAuth2AccessTokenMatchers(ClaimConstants.JTI, jti);
    }

    @Factory
    public static Matcher<OAuth2AccessToken> issuedAt(Matcher<Integer> iat) {
        return new OAuth2AccessTokenMatchers(ClaimConstants.IAT, iat);
    }

    @Factory
    public static Matcher<OAuth2AccessToken> expiry(Matcher<Integer> expiry) {
        return new OAuth2AccessTokenMatchers(ClaimConstants.EXP, expiry);
    }

    @Factory
    public static Matcher<OAuth2AccessToken> username(Matcher<Object> username) {
        return new OAuth2AccessTokenMatchers(ClaimConstants.USER_NAME, username);
    }

    @Factory
    public static <T> Matcher<OAuth2AccessToken> zoneId(Matcher<Object> zoneId) {
        return new OAuth2AccessTokenMatchers(ClaimConstants.ZONE_ID, zoneId);
    }

    @Factory
    public static <T> Matcher<OAuth2AccessToken> origin(Matcher<Object> origin) {
        return new OAuth2AccessTokenMatchers(ClaimConstants.ORIGIN, origin);
    }

    @Factory
    public static <T> Matcher<OAuth2AccessToken> revocationSignature(Matcher<Object> signature) {
        return new OAuth2AccessTokenMatchers(ClaimConstants.REVOCATION_SIGNATURE, signature);
    }

    @Factory
    public static <T> Matcher<OAuth2AccessToken> email(Matcher<Object> email) {
        return new OAuth2AccessTokenMatchers(ClaimConstants.EMAIL, email);
    }

    @Factory
    public static Matcher<OAuth2AccessToken> validFor(Matcher<?> validFor) {
        return new AbstractOAuth2AccessTokenMatchers<OAuth2AccessToken>(validFor) {

            @Override
            protected boolean matchesSafely(OAuth2AccessToken token) {
                Map<String, Object> claims = getClaims(token);
                assertTrue(((Integer) claims.get(ClaimConstants.IAT)) > 0);
                assertTrue(((Integer) claims.get(ClaimConstants.EXP)) > 0);
                return value.matches(((Integer) claims.get(ClaimConstants.EXP)) - ((Integer) claims.get(ClaimConstants.IAT)));
            }

            @Override
            public void describeTo(Description description) {
                description.appendText("should be valid for ").appendValue(value);
            }

            @Override
            protected void describeMismatchSafely(OAuth2AccessToken accessToken, Description mismatchDescription) {
                if (accessToken != null) {
                    Map<String, Object> claims = getClaims(accessToken);
                    mismatchDescription.appendText(" but was ").appendValue(((Integer) claims.get(ClaimConstants.EXP)) - ((Integer) claims.get(ClaimConstants.IAT)));
                }
            }
        };
    }
}
