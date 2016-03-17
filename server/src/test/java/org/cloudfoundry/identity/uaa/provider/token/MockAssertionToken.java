package org.cloudfoundry.identity.uaa.provider.token;

import java.util.LinkedHashMap;
import java.util.Map;

import org.apache.commons.codec.binary.Base64;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.RsaSigner;

public class MockAssertionToken {

    private final RsaSigner signer;

    public MockAssertionToken(final String tokenSigningKey) {
        this.signer = new RsaSigner(tokenSigningKey);
    }

    public MockAssertionToken() {
        this.signer = new RsaSigner(TestKeys.TOKEN_SIGNING_KEY);
    }

    public String mockAssertionToken(final String issuerId, final long issuedAtMillis, final long validitySeconds,
            final String tenantId, final String audience) {
        Object expiration = (issuedAtMillis + (validitySeconds * 1000L)) / 1000L;
        return createAssertionToken(issuerId, issuerId, validitySeconds, audience,issuedAtMillis, tenantId, expiration);
    }
    
    public String mockInvalidExpirationAssertionToken(final String issuerId, final long issuedAtMillis, final long validitySeconds,
            final String tenantId, final String audience, final Object expiration) {
        return createAssertionToken(issuerId, issuerId, validitySeconds, audience,issuedAtMillis, tenantId, expiration);
    }

    private String createAssertionToken(final String issuerId, final String userId,
            final long validitySeconds, final String resourceId,
            final long issuedAtMillis, final String tenantId, final Object expiration) {

        String content;
        try {
            content = JsonUtils.writeValueAsString(createClaims(issuerId, userId, resourceId,issuedAtMillis,
                    expiration, tenantId));
        } catch (JsonUtils.JsonUtilException e) {
            throw new IllegalStateException("Cannot convert access token to JSON", e);
        }
        return JwtHelper.encode(content, this.signer).getEncoded();
    }

    private static Map<String, ?> createClaims(final String issuerId,
            final String userId, final String audience, final long issuedAtMillis,
            final Object expiration, final String tenantId) {
        Map<String, Object> response = new LinkedHashMap<String, Object>();
        response.put(ClaimConstants.SUB, userId);
        response.put(ClaimConstants.TENANT_ID, tenantId);
        response.put(ClaimConstants.IAT, issuedAtMillis / 1000L);
        response.put(ClaimConstants.EXP, expiration);
        response.put(ClaimConstants.ISS, issuerId);
        response.put(ClaimConstants.AUD, audience);

        return response;
    }

}