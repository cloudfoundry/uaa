package org.cloudfoundry.identity.uaa.oauth;

import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

public class KeyInfoBuilder {

    public static KeyInfo build(String keyId, String signingKey, String uaaUrl) {
        return build(keyId, signingKey, uaaUrl, null);
    }
    public static KeyInfo build(String keyId, String signingKey, String uaaUrl, String sigAlg) {
        if (StringUtils.isEmpty(signingKey)) {
            throw new IllegalArgumentException("Signing key cannot be empty");
        }

        Assert.hasText(signingKey, "[Assertion failed] - this String argument must have text; it must not be null, empty, or blank");
        signingKey = signingKey.trim();

        if (isAssymetricKey(signingKey)) {
            return new RsaKeyInfo(keyId, signingKey, uaaUrl, sigAlg);
        }
        return new HmacKeyInfo(keyId, signingKey, uaaUrl, sigAlg);
    }

    /**
     * @return true if the string represents an asymmetric (RSA) key
     */
    private static boolean isAssymetricKey(String key) {
        return key.startsWith("-----BEGIN");
    }
}
