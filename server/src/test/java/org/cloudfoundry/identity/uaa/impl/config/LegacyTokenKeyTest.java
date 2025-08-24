package org.cloudfoundry.identity.uaa.impl.config;

import org.cloudfoundry.identity.uaa.oauth.KeyInfo;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class LegacyTokenKeyTest {

    @Test
    void shouldBuildLegacyTokenKey_withSecureKeyUrl() {
        LegacyTokenKey.setLegacySigningKey("secret", "http://uaa.url");

        KeyInfo legacyTokenKeyInfo = LegacyTokenKey.getLegacyTokenKeyInfo();

        assertThat(legacyTokenKeyInfo.keyURL()).isEqualTo("https://uaa.url/token_keys");
    }

    @Test
    void shouldBuildLegacyTokenKey() {
        LegacyTokenKey.setLegacySigningKey("secret", "https://another.uaa.url");

        KeyInfo legacyTokenKeyInfo = LegacyTokenKey.getLegacyTokenKeyInfo();

        assertThat(legacyTokenKeyInfo.keyURL()).isEqualTo("https://another.uaa.url/token_keys");
    }

    @Test
    void buildLegacyTokenKey_withInvalidKeyUrl() {
        assertThatThrownBy(() -> LegacyTokenKey.setLegacySigningKey("secret", "not a valid url"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Invalid Key URL");
    }
}
