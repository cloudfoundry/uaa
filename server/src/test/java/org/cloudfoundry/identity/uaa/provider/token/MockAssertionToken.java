package org.cloudfoundry.identity.uaa.provider.token;

import java.security.interfaces.RSAPrivateKey;
import java.util.LinkedHashMap;
import java.util.Map;

import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.RsaSigner;
public class MockAssertionToken {

    private final RsaSigner signer;

    public MockAssertionToken(final String tokenSigningKey) {
        this.signer = new RsaSigner(tokenSigningKey);
    }

    /**
     * Create a mock with D1 signer
     */
    public MockAssertionToken() {
        this.signer = new RsaSigner(MockKeyProvider.DEVICE1_PRIVATE_KEY);
    }
    
    public MockAssertionToken(RSAPrivateKey tokenSigningKey) {
        this.signer = new RsaSigner(tokenSigningKey);
    }

    public String mockAssertionToken(String issuer, final String subject, final long issuedAtMillis,
            final long validitySeconds, final String tenantId, final Object audience) {
        Object expiration = (issuedAtMillis + (validitySeconds * 1000L)) / 1000L;
        return createAssertionToken(issuer, subject, audience, issuedAtMillis, tenantId, expiration);
    }

    public String mockInvalidExpirationAssertionToken(String issuer, final String subject,
            final long issuedAtMillis, final String tenantId, final Object audience, final Object expiration) {
        return createAssertionToken(issuer, subject, audience, issuedAtMillis, tenantId, expiration);
    }


    private String createAssertionToken(String issuer, String subject, Object audience,
             final long issuedAtMillis, final String tenantId, final Object expiration) {

        String content;
        try {
            content = JsonUtils.writeValueAsString(
                    createClaims(issuer, subject, audience, issuedAtMillis, expiration, tenantId));
        } catch (JsonUtils.JsonUtilException e) {
            throw new IllegalStateException("Cannot convert access token to JSON", e);
        }
        return JwtHelper.encode(content, this.signer).getEncoded();
    }

    static Map<String, ?> createClaims(String issuer, String subject, final Object audience,
             final long issuedAtMillis, final Object expiration, final String tenantId) {
        Map<String, Object> response = new LinkedHashMap<String, Object>();
        response.put(ClaimConstants.ISS, issuer);
        response.put(ClaimConstants.SUB, subject);
        response.put(ClaimConstants.TENANT_ID, tenantId);
        response.put(ClaimConstants.IAT, issuedAtMillis / 1000L);

        if (expiration != null) {
            response.put(ClaimConstants.EXPIRY_IN_SECONDS, expiration);
        }
        response.put(ClaimConstants.AUD, audience);

        return response;
    }

}