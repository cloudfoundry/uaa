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
}
