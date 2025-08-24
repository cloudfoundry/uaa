package org.cloudfoundry.identity.uaa.oauth.token.matchers;

import org.cloudfoundry.identity.uaa.oauth.common.OAuth2RefreshToken;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.hamcrest.Description;
import org.hamcrest.Matcher;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

public class OAuth2RefreshTokenMatchers extends AbstractOAuth2AccessTokenMatchers<OAuth2RefreshToken> {

    private final String key;

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

    public static Matcher<OAuth2RefreshToken> issuerUri(Matcher<Object> issuerUri) {
        return new OAuth2RefreshTokenMatchers(ClaimConstants.ISS, issuerUri);
    }

    public static Matcher<OAuth2RefreshToken> clientId(Matcher<Object> clientId) {
        return new OAuth2RefreshTokenMatchers(ClaimConstants.CLIENT_ID, clientId);
    }

    public static Matcher<OAuth2RefreshToken> userId(Matcher<Object> userId) {
        return new OAuth2RefreshTokenMatchers(ClaimConstants.USER_ID, userId);
    }

    public static Matcher<OAuth2RefreshToken> subject(Matcher<Object> clientId) {
        return new OAuth2RefreshTokenMatchers(ClaimConstants.SUB, clientId);
    }

    public static Matcher<OAuth2RefreshToken> cid(Matcher<Object> clientId) {
        return new OAuth2RefreshTokenMatchers(ClaimConstants.CID, clientId);
    }

    public static Matcher<OAuth2RefreshToken> scope(Matcher<Object> scopes) {
        return new OAuth2RefreshTokenMatchers(ClaimConstants.GRANTED_SCOPES, scopes);
    }

    public static Matcher<OAuth2RefreshToken> audience(Matcher<Iterable<? extends String>> resourceIds) {
        return new OAuth2RefreshTokenMatchers(ClaimConstants.AUD, resourceIds);
    }

    public static Matcher<OAuth2RefreshToken> jwtId(Matcher<String> jti) {
        return new OAuth2RefreshTokenMatchers(ClaimConstants.JTI, jti);
    }

    public static Matcher<OAuth2RefreshToken> issuedAt(Matcher<Integer> iat) {
        return new OAuth2RefreshTokenMatchers(ClaimConstants.IAT, iat);
    }

    public static Matcher<OAuth2RefreshToken> expiry(Matcher<Integer> expiry) {
        return new OAuth2RefreshTokenMatchers(ClaimConstants.EXPIRY_IN_SECONDS, expiry);
    }

    public static Matcher<OAuth2RefreshToken> username(Matcher<Object> username) {
        return new OAuth2RefreshTokenMatchers(ClaimConstants.USER_NAME, username);
    }

    public static Matcher<OAuth2RefreshToken> zoneId(Matcher<Object> zoneId) {
        return new OAuth2RefreshTokenMatchers(ClaimConstants.ZONE_ID, zoneId);
    }

    public static Matcher<OAuth2RefreshToken> origin(Matcher<Object> origin) {
        return new OAuth2RefreshTokenMatchers(ClaimConstants.ORIGIN, origin);
    }

    public static Matcher<OAuth2RefreshToken> revocationSignature(Matcher<Object> signature) {
        return new OAuth2RefreshTokenMatchers(ClaimConstants.REVOCATION_SIGNATURE, signature);
    }

    public static Matcher<OAuth2RefreshToken> email(Matcher<Object> email) {
        return new OAuth2RefreshTokenMatchers(ClaimConstants.EMAIL, email);
    }

    public static Matcher<OAuth2RefreshToken> validFor(Matcher<?> validFor) {
        return new AbstractOAuth2AccessTokenMatchers<>() {

            @Override
            protected boolean matchesSafely(OAuth2RefreshToken token) {
                Map<String, Object> claims = getClaims(token);
                assertThat(((Integer) claims.get(ClaimConstants.IAT))).isPositive();
                assertThat(((Integer) claims.get(ClaimConstants.EXPIRY_IN_SECONDS))).isPositive();
                return validFor.matches(((Integer) claims.get(ClaimConstants.EXPIRY_IN_SECONDS)) - ((Integer) claims.get(ClaimConstants.IAT)));
            }

            @Override
            public void describeTo(Description description) {
                description.appendText("Refresh token should be valid for ").appendValue(value);
            }

            @Override
            protected void describeMismatchSafely(OAuth2RefreshToken accessToken, Description mismatchDescription) {
                if (accessToken != null) {
                    Map<String, Object> claims = getClaims(accessToken);
                    mismatchDescription.appendText(" was ").appendValue(((Integer) claims.get(ClaimConstants.EXPIRY_IN_SECONDS)) - ((Integer) claims.get(ClaimConstants.IAT)));
                }
            }
        };
    }
}
