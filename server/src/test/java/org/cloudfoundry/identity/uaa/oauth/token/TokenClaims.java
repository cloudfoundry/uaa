package org.cloudfoundry.identity.uaa.oauth.token;

import tools.jackson.core.type.TypeReference;
import org.cloudfoundry.identity.uaa.oauth.KeyInfoService;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2RefreshToken;
import org.cloudfoundry.identity.uaa.oauth.jwt.Jwt;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.util.JsonUtils;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test-only helper that decodes and verifies the JWT claims of an {@link OAuth2AccessToken} or
 * {@link OAuth2RefreshToken}, replacing the removed Hamcrest-based token matcher hierarchy.
 * Call sites should use the per-claim accessors below with plain AssertJ assertions, e.g.
 * {@code assertThat(TokenClaims.cid(accessToken)).isEqualTo(CLIENT_ID);}
 */
public final class TokenClaims {

    /**
     * Some tests register {@link org.cloudfoundry.identity.uaa.oauth.token.RevocableToken}s under an opaque
     * token id; when set, the claims lookup resolves the JWT value through this map before decoding.
     */
    public static final ThreadLocal<Map<String, RevocableToken>> revocableTokens = ThreadLocal.withInitial(Collections::emptyMap);

    private static final KeyInfoService KEY_INFO_SERVICE = new KeyInfoService("https://localhost/uaa");

    private TokenClaims() {
    }

    public static Map<String, Object> claims(OAuth2AccessToken accessToken) {
        return claims(accessToken.getValue());
    }

    public static Map<String, Object> claims(OAuth2RefreshToken refreshToken) {
        return claims(refreshToken.getValue());
    }

    public static Object claim(OAuth2AccessToken accessToken, String key) {
        return claims(accessToken).get(key);
    }

    public static Object claim(OAuth2RefreshToken refreshToken, String key) {
        return claims(refreshToken).get(key);
    }

    public static String issuerUri(OAuth2AccessToken accessToken) {
        return (String) claim(accessToken, ClaimConstants.ISS);
    }

    public static String issuerUri(OAuth2RefreshToken refreshToken) {
        return (String) claim(refreshToken, ClaimConstants.ISS);
    }

    public static String clientId(OAuth2AccessToken accessToken) {
        return (String) claim(accessToken, ClaimConstants.CLIENT_ID);
    }

    public static String clientId(OAuth2RefreshToken refreshToken) {
        return (String) claim(refreshToken, ClaimConstants.CLIENT_ID);
    }

    public static String userId(OAuth2AccessToken accessToken) {
        return (String) claim(accessToken, ClaimConstants.USER_ID);
    }

    public static String userId(OAuth2RefreshToken refreshToken) {
        return (String) claim(refreshToken, ClaimConstants.USER_ID);
    }

    public static Object subject(OAuth2AccessToken accessToken) {
        return claim(accessToken, ClaimConstants.SUB);
    }

    public static Object subject(OAuth2RefreshToken refreshToken) {
        return claim(refreshToken, ClaimConstants.SUB);
    }

    public static String cid(OAuth2AccessToken accessToken) {
        return (String) claim(accessToken, ClaimConstants.CID);
    }

    public static String cid(OAuth2RefreshToken refreshToken) {
        return (String) claim(refreshToken, ClaimConstants.CID);
    }

    @SuppressWarnings("unchecked")
    public static List<String> scope(OAuth2AccessToken accessToken) {
        return (List<String>) claim(accessToken, ClaimConstants.SCOPE);
    }

    @SuppressWarnings("unchecked")
    public static List<String> scope(OAuth2RefreshToken refreshToken) {
        return (List<String>) claim(refreshToken, ClaimConstants.GRANTED_SCOPES);
    }

    @SuppressWarnings("unchecked")
    public static List<String> audience(OAuth2AccessToken accessToken) {
        return (List<String>) claim(accessToken, ClaimConstants.AUD);
    }

    @SuppressWarnings("unchecked")
    public static List<String> audience(OAuth2RefreshToken refreshToken) {
        return (List<String>) claim(refreshToken, ClaimConstants.AUD);
    }

    public static String jwtId(OAuth2AccessToken accessToken) {
        return (String) claim(accessToken, ClaimConstants.JTI);
    }

    public static String jwtId(OAuth2RefreshToken refreshToken) {
        return (String) claim(refreshToken, ClaimConstants.JTI);
    }

    public static Integer issuedAt(OAuth2AccessToken accessToken) {
        return (Integer) claim(accessToken, ClaimConstants.IAT);
    }

    public static Integer issuedAt(OAuth2RefreshToken refreshToken) {
        return (Integer) claim(refreshToken, ClaimConstants.IAT);
    }

    public static Integer expiry(OAuth2AccessToken accessToken) {
        return (Integer) claim(accessToken, ClaimConstants.EXPIRY_IN_SECONDS);
    }

    public static Integer expiry(OAuth2RefreshToken refreshToken) {
        return (Integer) claim(refreshToken, ClaimConstants.EXPIRY_IN_SECONDS);
    }

    public static String username(OAuth2AccessToken accessToken) {
        return (String) claim(accessToken, ClaimConstants.USER_NAME);
    }

    public static String username(OAuth2RefreshToken refreshToken) {
        return (String) claim(refreshToken, ClaimConstants.USER_NAME);
    }

    public static String zoneId(OAuth2AccessToken accessToken) {
        return (String) claim(accessToken, ClaimConstants.ZONE_ID);
    }

    public static String zoneId(OAuth2RefreshToken refreshToken) {
        return (String) claim(refreshToken, ClaimConstants.ZONE_ID);
    }

    public static String origin(OAuth2AccessToken accessToken) {
        return (String) claim(accessToken, ClaimConstants.ORIGIN);
    }

    public static String origin(OAuth2RefreshToken refreshToken) {
        return (String) claim(refreshToken, ClaimConstants.ORIGIN);
    }

    public static Object revocationSignature(OAuth2AccessToken accessToken) {
        return claim(accessToken, ClaimConstants.REVOCATION_SIGNATURE);
    }

    public static Object revocationSignature(OAuth2RefreshToken refreshToken) {
        return claim(refreshToken, ClaimConstants.REVOCATION_SIGNATURE);
    }

    public static String email(OAuth2AccessToken accessToken) {
        return (String) claim(accessToken, ClaimConstants.EMAIL);
    }

    public static String email(OAuth2RefreshToken refreshToken) {
        return (String) claim(refreshToken, ClaimConstants.EMAIL);
    }

    /**
     * Number of seconds the token is valid for: {@code exp - iat}. Asserts (as the original matcher did)
     * that both claims are present and positive before computing the difference.
     */
    public static int validFor(OAuth2AccessToken accessToken) {
        Map<String, Object> claims = claims(accessToken);
        return validFor(claims);
    }

    public static int validFor(OAuth2RefreshToken refreshToken) {
        Map<String, Object> claims = claims(refreshToken);
        return validFor(claims);
    }

    private static int validFor(Map<String, Object> claims) {
        Integer iat = (Integer) claims.get(ClaimConstants.IAT);
        Integer exp = (Integer) claims.get(ClaimConstants.EXPIRY_IN_SECONDS);
        assertThat(iat).isPositive();
        assertThat(exp).isPositive();
        return exp - iat;
    }

    private static String resolveTokenValue(String token) {
        Map<String, RevocableToken> tokens = revocableTokens.get();
        if (tokens.containsKey(token)) {
            return tokens.get(token).getValue();
        }
        return token;
    }

    private static Map<String, Object> claims(String tokenValue) {
        Jwt tokenJwt = JwtHelper.decode(resolveTokenValue(tokenValue));
        assertThat(tokenJwt).isNotNull();
        Map<String, Object> claims;
        try {
            claims = JsonUtils.readValue(tokenJwt.getClaims(), new TypeReference<>() {
            });
        } catch (Exception e) {
            throw new IllegalArgumentException("Unable to decode token", e);
        }
        tokenJwt.verifySignature(KEY_INFO_SERVICE.getKey(tokenJwt.getHeader().getKid()).getVerifier());
        return claims;
    }
}
