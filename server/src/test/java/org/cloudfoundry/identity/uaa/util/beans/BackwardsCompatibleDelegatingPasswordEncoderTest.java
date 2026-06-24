package org.cloudfoundry.identity.uaa.util.beans;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class BackwardsCompatibleDelegatingPasswordEncoderTest {

    private BCryptPasswordEncoder mockPasswordEncoder;
    private PasswordEncoder encoder;

    @BeforeEach
    void setUp() {
        mockPasswordEncoder = mock(BCryptPasswordEncoder.class);
        encoder = new BackwardsCompatibleDelegatingPasswordEncoder(mockPasswordEncoder);
    }

    @Nested
    class ByDefault {

        @Test
        void encode() {
            when(mockPasswordEncoder.encode("password")).thenReturn("encodedPassword");
            assertThat(encoder.encode("password")).isEqualTo("encodedPassword");
        }

        @Test
        void matches() {
            when(mockPasswordEncoder.matches("password", "encodedPassword")).thenReturn(true);
            assertThat(encoder.matches("password", "encodedPassword")).isTrue();
        }

        @Test
        void onlyNullPasswordMatchesNullEncodedPassword() {
            assertThat(encoder.matches(null, null)).isTrue();
            assertThat(encoder.matches("", null)).isFalse();
        }
    }

    @Nested
    class WithMultipleDecodeOptions {

        @Test
        void encode() {
            when(mockPasswordEncoder.encode("password")).thenReturn("encodedPassword");
            assertThat(encoder.encode("password")).isEqualTo("encodedPassword");
        }

        @Test
        void doesNotMatchArbitraryPrefix() {
            assertThatThrownBy(() -> encoder.matches("password", "{prefix}encodedPassword"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Password encoding {prefix} is not supported");

            assertThatThrownBy(() -> encoder.matches("password", "{otherprefix}encodedPassword"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Password encoding {otherprefix} is not supported");

            verifyNoInteractions(mockPasswordEncoder);
        }

        @Test
        void doesNotMatchInvalidPrefix() {
            assertThat(encoder.matches("password", "aaa{bcrypt}encodedPassword")).isFalse();
            verify(mockPasswordEncoder).matches("password", "aaa{bcrypt}encodedPassword");
        }

        @Test
        void matchesBcryptPrefixOnly() {
            when(mockPasswordEncoder.matches("password", "encodedPassword")).thenReturn(true);
            assertThat(encoder.matches("password", "{bcrypt}encodedPassword")).isTrue();
            verify(mockPasswordEncoder).matches("password", "encodedPassword");
        }
    }

    @Nested
    class WithEmptyPassword {
        // Spring Security 7's BCryptPasswordEncoder extends AbstractValidatingPasswordEncoder
        // which short-circuits matches() and returns false for empty rawPassword.
        // UAA legitimately stores BCrypt hashes of empty strings (clients with no secret,
        // e.g. the CF CLI client). Verify that this class handles empty rawPassword correctly
        // so ClientAdminBootstrap.updatePasswordsIfChanged() does not re-encode on every startup.
        private final BCryptPasswordEncoder realEncoder = new BCryptPasswordEncoder();
        private final PasswordEncoder realBackwardsEncoder =
                new BackwardsCompatibleDelegatingPasswordEncoder(realEncoder);

        @Test
        void emptyPasswordMatchesItsOwnHash() {
            String hash = realEncoder.encode("");
            assertThat(realBackwardsEncoder.matches("", hash)).isTrue();
        }

        @Test
        void emptyPasswordDoesNotMatchDifferentHash() {
            String hash = realEncoder.encode("notempty");
            assertThat(realBackwardsEncoder.matches("", hash)).isFalse();
        }

        @Test
        void emptyPasswordMatchesBcryptPrefixedHash() {
            String hash = "{bcrypt}" + realEncoder.encode("");
            assertThat(realBackwardsEncoder.matches("", hash)).isTrue();
        }
    }
}
