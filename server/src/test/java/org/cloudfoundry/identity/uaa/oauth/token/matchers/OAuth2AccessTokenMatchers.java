package org.cloudfoundry.identity.uaa.oauth.token.matchers;

import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.hamcrest.Description;
import org.hamcrest.Matcher;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

public class OAuth2AccessTokenMatchers extends AbstractOAuth2AccessTokenMatchers<OAuth2AccessToken> {

    private final String key;

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

    public static Matcher<OAuth2AccessToken> issuerUri(Matcher<Object> issuerUri) {
        return new OAuth2AccessTokenMatchers(ClaimConstants.ISS, issuerUri);
    }

    public static Matcher<OAuth2AccessToken> clientId(Matcher<Object> clientId) {
        return new OAuth2AccessTokenMatchers(ClaimConstants.CLIENT_ID, clientId);
    }

    public static Matcher<OAuth2AccessToken> userId(Matcher<Object> userId) {
        return new OAuth2AccessTokenMatchers(ClaimConstants.USER_ID, userId);
    }

    public static Matcher<OAuth2AccessToken> subject(Matcher<Object> clientId) {
        return new OAuth2AccessTokenMatchers(ClaimConstants.SUB, clientId);
    }

    public static Matcher<OAuth2AccessToken> cid(Matcher<Object> clientId) {
        return new OAuth2AccessTokenMatchers(ClaimConstants.CID, clientId);
    }

    public static Matcher<OAuth2AccessToken> scope(Matcher<Object> scopes) {
        return new OAuth2AccessTokenMatchers(ClaimConstants.SCOPE, scopes);
    }

    public static Matcher<OAuth2AccessToken> audience(Matcher<Iterable<? extends String>> resourceIds) {
        return new OAuth2AccessTokenMatchers(ClaimConstants.AUD, resourceIds);
    }

    public static Matcher<OAuth2AccessToken> jwtId(Matcher<String> jti) {
        return new OAuth2AccessTokenMatchers(ClaimConstants.JTI, jti);
    }

    public static Matcher<OAuth2AccessToken> issuedAt(Matcher<Integer> iat) {
        return new OAuth2AccessTokenMatchers(ClaimConstants.IAT, iat);
    }

    public static Matcher<OAuth2AccessToken> expiry(Matcher<Integer> expiry) {
        return new OAuth2AccessTokenMatchers(ClaimConstants.EXPIRY_IN_SECONDS, expiry);
    }

    public static Matcher<OAuth2AccessToken> username(Matcher<Object> username) {
        return new OAuth2AccessTokenMatchers(ClaimConstants.USER_NAME, username);
    }

    public static Matcher<OAuth2AccessToken> zoneId(Matcher<Object> zoneId) {
        return new OAuth2AccessTokenMatchers(ClaimConstants.ZONE_ID, zoneId);
    }

    public static Matcher<OAuth2AccessToken> origin(Matcher<Object> origin) {
        return new OAuth2AccessTokenMatchers(ClaimConstants.ORIGIN, origin);
    }

    public static Matcher<OAuth2AccessToken> revocationSignature(Matcher<Object> signature) {
        return new OAuth2AccessTokenMatchers(ClaimConstants.REVOCATION_SIGNATURE, signature);
    }

    public static Matcher<OAuth2AccessToken> email(Matcher<Object> email) {
        return new OAuth2AccessTokenMatchers(ClaimConstants.EMAIL, email);
    }

    public static Matcher<OAuth2AccessToken> validFor(Matcher<?> validFor) {
        return new AbstractOAuth2AccessTokenMatchers<>(validFor) {

            @Override
            protected boolean matchesSafely(OAuth2AccessToken token) {
                Map<String, Object> claims = getClaims(token);
                assertThat(((Integer) claims.get(ClaimConstants.IAT))).isPositive();
                assertThat(((Integer) claims.get(ClaimConstants.EXPIRY_IN_SECONDS))).isPositive();
                return value.matches(((Integer) claims.get(ClaimConstants.EXPIRY_IN_SECONDS)) - ((Integer) claims.get(ClaimConstants.IAT)));
            }

            @Override
            public void describeTo(Description description) {
                description.appendText("should be valid for ").appendValue(value);
            }

            @Override
            protected void describeMismatchSafely(OAuth2AccessToken accessToken, Description mismatchDescription) {
                if (accessToken != null) {
                    Map<String, Object> claims = getClaims(accessToken);
                    mismatchDescription.appendText(" but was ").appendValue(((Integer) claims.get(ClaimConstants.EXPIRY_IN_SECONDS)) - ((Integer) claims.get(ClaimConstants.IAT)));
                }
            }
        };
    }
}
