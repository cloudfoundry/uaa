package org.cloudfoundry.identity.uaa.provider.token;

import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

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

    public String mockAssertionToken(final String issuerId, final long issuedAtMillis, final int validitySeconds,
            final String tenantId, final String audience) {
        Set<String> audienceSet = new HashSet<>(Arrays.asList(new String[] { audience }));
        return createAssertionToken(issuerId, issuerId, validitySeconds, audienceSet,issuedAtMillis, tenantId);
    }

    private String createAssertionToken(final String issuerId, final String userId,
            final int validitySeconds, final Set<String> resourceIds,
            final long issuedAtMillis, final String tenantId) {

        String content;
        try {
            content = JsonUtils.writeValueAsString(createClaims(issuerId, userId, resourceIds,issuedAtMillis,
                    validitySeconds, tenantId));
        } catch (JsonUtils.JsonUtilException e) {
            throw new IllegalStateException("Cannot convert access token to JSON", e);
        }
        return JwtHelper.encode(content, this.signer).getEncoded();
    }

    private static Map<String, ?> createClaims(final String issuerId,
            final String userId, final Set<String> audience, final long issuedAtMillis,
            final int validitySeconds, final String tenantId) {
        Map<String, Object> response = new LinkedHashMap<String, Object>();
        response.put(ClaimConstants.SUB, userId);
        response.put(ClaimConstants.TENANT_ID, tenantId);
        response.put(ClaimConstants.IAT, issuedAtMillis / 1000);
        response.put(ClaimConstants.EXP, (issuedAtMillis + (validitySeconds * 1000L)) / 1000);
        response.put(ClaimConstants.ISS, issuerId);
        response.put(ClaimConstants.AUD, audience);

        return response;
    }

}
