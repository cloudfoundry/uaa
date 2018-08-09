package org.cloudfoundry.identity.uaa.impl.config;

import org.cloudfoundry.identity.uaa.oauth.KeyInfo;
import org.cloudfoundry.identity.uaa.oauth.KeyInfoBuilder;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;

public final class LegacyTokenKey {
    public static final String LEGACY_TOKEN_KEY_ID = "legacy-token-key";
    private static KeyInfo keyInfo;

    private LegacyTokenKey() {
    }

    public static void setLegacySigningKey(String legacySigningKey, String keyUrl) {
        if (!StringUtils.hasText(legacySigningKey)) {
            return;
        }

        if (!UaaUrlUtils.isUrl(keyUrl)) {
            throw new IllegalArgumentException("Invalid key URL");
        }

        String secureTokenKeyUrl = UriComponentsBuilder.fromHttpUrl(keyUrl).scheme("https").path("token_keys").build().toUriString();
        LegacyTokenKey.keyInfo = KeyInfoBuilder.build(LEGACY_TOKEN_KEY_ID, legacySigningKey, secureTokenKeyUrl);
    }

    public static KeyInfo getLegacyTokenKeyInfo() {
        return keyInfo;
    }
}
