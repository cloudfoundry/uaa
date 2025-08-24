package org.cloudfoundry.identity.uaa.mock.util;

import com.fasterxml.jackson.core.type.TypeReference;
import org.cloudfoundry.identity.uaa.oauth.KeyInfoService;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidTokenException;
import org.cloudfoundry.identity.uaa.oauth.jwt.Jwt;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.util.JsonUtils;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

public class JwtTokenUtils {
    public static Map<String, Object> getClaimsForToken(String token) {
        Jwt tokenJwt;
        try {
            tokenJwt = JwtHelper.decode(token);
        } catch (Throwable t) {
            throw new InvalidTokenException("Invalid token (could not decode): " + token);
        }

        Map<String, Object> claims;
        try {
            claims = JsonUtils.readValue(tokenJwt.getClaims(), new TypeReference<Map<String, Object>>() {
            });
        } catch (Exception e) {
            throw new IllegalStateException("Cannot read token claims", e);
        }

        String kid = tokenJwt.getHeader().getKid();
        assertThat(kid).as("Token should have a key ID.").isNotNull();
        tokenJwt.verifySignature(new KeyInfoService("https://some-uaa").getKey(kid).getVerifier());

        return claims;
    }
}
