package org.cloudfoundry.identity.uaa.impl.config;

import org.cloudfoundry.identity.uaa.oauth.KeyInfo;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import static org.hamcrest.CoreMatchers.is;

public class LegacyTokenKeyTest {
    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Test
    public void shouldBuildLegacyTokenKey_withSecureKeyUrl() {
        LegacyTokenKey.setLegacySigningKey("secret", "http://uaa.url");

        KeyInfo legacyTokenKeyInfo = LegacyTokenKey.getLegacyTokenKeyInfo();

        Assert.assertThat(legacyTokenKeyInfo.keyURL(), is("https://uaa.url/token_keys"));
    }

    @Test
    public void shouldBuildLegacyTokenKey() {
        LegacyTokenKey.setLegacySigningKey("secret", "https://another.uaa.url");

        KeyInfo legacyTokenKeyInfo = LegacyTokenKey.getLegacyTokenKeyInfo();

        Assert.assertThat(legacyTokenKeyInfo.keyURL(), is("https://another.uaa.url/token_keys"));
    }

    @Test
    public void buildLegacyTokenKey_withInvalidKeyUrl() {
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("Invalid Key URL");

        LegacyTokenKey.setLegacySigningKey("secret", "not a valid url");
    }

}