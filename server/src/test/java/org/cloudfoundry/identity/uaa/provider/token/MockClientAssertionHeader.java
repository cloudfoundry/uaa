package org.cloudfoundry.identity.uaa.provider.token;

import java.security.interfaces.RSAPrivateKey;
import java.util.LinkedHashMap;
import java.util.Map;

import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.RsaSigner;

public class MockClientAssertionHeader {
    private RsaSigner signer;

    public MockClientAssertionHeader() {
        this.signer = new RsaSigner(MockKeyProvider.DEVICE1_PRIVATE_KEY);
    }
    
    public MockClientAssertionHeader(RSAPrivateKey signingKey) {
        this.signer = new RsaSigner(signingKey);
    }

    public String mockSignedHeader(Long iat, String devicedId, String tenantId) {
        return JwtHelper.encode(mockHeaderContent(iat, devicedId, tenantId), this.signer).getEncoded();
    }

    public String mockIncorrectlySignedHeader(final String devicedId, final String tenantId) {
        long currentTimeSecs = System.currentTimeMillis() / 1000;
        return JwtHelper.encode(mockHeaderContent(currentTimeSecs, devicedId, tenantId), 
                new RsaSigner(MockKeyProvider.INCORRECT_TOKEN_SIGNING_KEY)).getEncoded();
    }

    private String mockHeaderContent(Long iat, final String devicedId, final String tenantId) {
        String content;
        try {
            content = JsonUtils.writeValueAsString(createClaims(iat, devicedId, tenantId));
        } catch (JsonUtils.JsonUtilException e) {
            throw new IllegalStateException("Cannot convert access token to JSON", e);
        }
        return content;
    }

    private Map<String, ?> createClaims(Long iat, final String devicedId, final String tenantId) {
        Map<String, Object> response = new LinkedHashMap<String, Object>();
        response.put(ClaimConstants.IAT, iat);
        response.put(ClaimConstants.SUB, devicedId);
        response.put(ClaimConstants.TENANT_ID, tenantId);
        return response;
    }
}
