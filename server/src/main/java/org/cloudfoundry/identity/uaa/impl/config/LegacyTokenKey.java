package org.cloudfoundry.identity.uaa.impl.config;

import org.cloudfoundry.identity.uaa.oauth.KeyInfo;
import org.cloudfoundry.identity.uaa.oauth.KeyInfoBuilder;
import org.springframework.util.StringUtils;

public final class LegacyTokenKey {
    public static final String LEGACY_TOKEN_KEY_ID = "legacy-token-key";
    private static KeyInfo keyInfo;

    private LegacyTokenKey() {
    }

    public static void setLegacySigningKey(String legacySigningKey, String uaaUrl) {
        if (!StringUtils.hasText(legacySigningKey)) {
            return;
        }

        LegacyTokenKey.keyInfo = KeyInfoBuilder.build(LEGACY_TOKEN_KEY_ID, legacySigningKey, uaaUrl);
    }

    public static KeyInfo getLegacyTokenKeyInfo() {
        return keyInfo;
    }
}
