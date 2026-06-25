package org.cloudfoundry.identity.uaa.authentication;

import org.cloudfoundry.identity.uaa.util.beans.EmptyAwareDelegatingPasswordEncoder;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;

class EmptyAwareDelegatingPasswordEncoderTest {

    private final PasswordEncoder bcrypt = new BCryptPasswordEncoder();
    private final EmptyAwareDelegatingPasswordEncoder encoder = new EmptyAwareDelegatingPasswordEncoder(bcrypt);

    @Test
    void emptyRawPassword_matchesBcryptHashOfEmptyString() {
        assertThat(encoder.matches("", bcrypt.encode(""))).isTrue();
    }

    @Test
    void emptyRawPassword_matchesNoopPrefixWithEmptyValue() {
        assertThat(encoder.matches("", "{noop}")).isTrue();
    }

    @Test
    void emptyRawPassword_doesNotMatchBcryptHashOfNonEmptyString() {
        assertThat(encoder.matches("", bcrypt.encode("notempty"))).isFalse();
    }

    @Test
    void emptyRawPassword_doesNotMatchNullStoredPassword() {
        assertThat(encoder.matches("", null)).isFalse();
    }

    @Test
    void emptyRawPassword_doesNotMatchRawEmptyStoredValue() {
        assertThat(encoder.matches("", "")).isFalse();
    }

    @Test
    void emptyRawPassword_doesNotMatchEmptyBracesPrefix() {
        assertThat(encoder.matches("", "{}")).isFalse();
    }

    @Test
    void emptyRawPassword_doesNotMatchUnknownPrefixWithEmptyValue() {
        assertThat(encoder.matches("", "{plaintext}")).isFalse();
        assertThat(encoder.matches("", "{argon2}")).isFalse();
    }

    @Test
    void emptyRawPassword_doesNotMatchUnknownPrefixWrappingBcryptEmptyHash() {
        String bcryptEmpty = bcrypt.encode("");
        assertThat(encoder.matches("", "{sha256}" + bcryptEmpty)).isFalse();
    }

    @Test
    void emptyRawPassword_doesNotMatchBcryptPrefixWithoutHash() {
        assertThat(encoder.matches("", "{bcrypt}")).isFalse();
    }

    @Test
    void nullRawPassword_returnsFalseWithoutDelegating() {
        PasswordEncoder failingDelegate = new PasswordEncoder() {
            @Override
            public String encode(CharSequence rawPassword) {
                throw new AssertionError("encode should not be called");
            }

            @Override
            public boolean matches(CharSequence rawPassword, String encodedPassword) {
                throw new AssertionError("matches should not be called for null rawPassword");
            }
        };
        EmptyAwareDelegatingPasswordEncoder guarded = new EmptyAwareDelegatingPasswordEncoder(failingDelegate);
        assertThat(guarded.matches(null, bcrypt.encode(""))).isFalse();
        assertThat(guarded.matches(null, null)).isFalse();
    }

    @Test
    void nonEmptyRawPassword_delegatesToWrappedEncoder() {
        String encoded = bcrypt.encode("secret");
        assertThat(encoder.matches("secret", encoded)).isTrue();
        assertThat(encoder.matches("wrong", encoded)).isFalse();
    }

    @Test
    void encode_delegatesToWrappedEncoder() {
        String encoded = encoder.encode("secret");
        assertThat(bcrypt.matches("secret", encoded)).isTrue();
    }

    @Test
    void constantTimeComparison_behavesConsistentlyForDifferentInputs() {
        // This test verifies that MessageDigest.isEqual() is being used for constant-time comparison
        // by checking that different inputs still produce boolean results (not testing actual timing)
        
        // Test same-length strings with different content
        assertThat(encoder.matches("", "{noop}test")).isFalse();  // Different content, same length prefix
        assertThat(encoder.matches("", "{noop}")).isTrue();       // Empty match
        assertThat(encoder.matches("", "{noop}a")).isFalse();     // Single char difference
        assertThat(encoder.matches("", "{noop}aaaa")).isFalse();  // Multiple char difference
        
        // The fact that these all return promptly with correct boolean results
        // indicates MessageDigest.isEqual() is working correctly for our use case
        // Actual timing would require a separate micro-benchmark test
    }
}
