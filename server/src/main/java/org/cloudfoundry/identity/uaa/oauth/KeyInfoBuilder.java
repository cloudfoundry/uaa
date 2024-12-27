package org.cloudfoundry.identity.uaa.oauth;

import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

public class KeyInfoBuilder {

    public static KeyInfo build(String keyId, String signingKey, String uaaUrl) {
        return build(keyId, signingKey, uaaUrl, null, null);
    }

    public static KeyInfo build(String keyId, String signingKey, String uaaUrl, String sigAlg, String signingCert) {
        if (StringUtils.isEmpty(signingKey)) {
            throw new IllegalArgumentException("Signing key cannot be empty");
        }

        Assert.hasText(signingKey, "[Assertion failed] - this String argument must have text; it must not be null, empty, or blank");
        signingKey = signingKey.trim();
        return new KeyInfo(keyId, signingKey, uaaUrl, sigAlg, signingCert);
    }
}
