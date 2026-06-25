package org.cloudfoundry.identity.uaa.util.beans;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.util.beans.SecureStringComparison.constantTimeEquals;

class SecureStringComparisonTest {

    @Test
    void constantTimeEquals_handlesNullValues() {
        assertThat(constantTimeEquals(null, null)).isTrue();
        assertThat(constantTimeEquals(null, "test")).isFalse();
        assertThat(constantTimeEquals("test", null)).isFalse();
    }

    @Test
    void constantTimeEquals_handlesEmptyStrings() {
        assertThat(constantTimeEquals("", "")).isTrue();
        assertThat(constantTimeEquals("", "test")).isFalse();
        assertThat(constantTimeEquals("test", "")).isFalse();
    }

    @Test
    void constantTimeEquals_handlesIdenticalStrings() {
        assertThat(constantTimeEquals("test", "test")).isTrue();
        assertThat(constantTimeEquals("password123", "password123")).isTrue();
        assertThat(constantTimeEquals("{noop}", "{noop}")).isTrue();
    }

    @Test
    void constantTimeEquals_handlesDifferentStrings() {
        assertThat(constantTimeEquals("test", "different")).isFalse();
        assertThat(constantTimeEquals("password123", "password124")).isFalse();
        assertThat(constantTimeEquals("{noop}", "{bcrypt}")).isFalse();
    }

    @Test
    void constantTimeEquals_handlesDifferentLengths() {
        assertThat(constantTimeEquals("short", "much_longer_string")).isFalse();
        assertThat(constantTimeEquals("much_longer_string", "short")).isFalse();
    }

    @Test
    void constantTimeEquals_handlesUnicodeCharacters() {
        assertThat(constantTimeEquals("café", "café")).isTrue();
        assertThat(constantTimeEquals("café", "cafe")).isFalse();
        assertThat(constantTimeEquals("🔒secure", "🔒secure")).isTrue();
        assertThat(constantTimeEquals("🔒secure", "🔓insecure")).isFalse();
    }

    @Test
    void constantTimeEquals_handlesCaseSensitivity() {
        assertThat(constantTimeEquals("Test", "test")).isFalse();
        assertThat(constantTimeEquals("PASSWORD", "password")).isFalse();
    }
}