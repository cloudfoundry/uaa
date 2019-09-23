package org.cloudfoundry.identity.uaa.util.beans;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.cloudfoundry.identity.uaa.util.AssertThrowsWithMessage.assertThrowsWithMessageThat;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;
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
            assertThat(encoder.encode("password"), is("encodedPassword"));
        }

        @Test
        void matches() {
            when(mockPasswordEncoder.matches("password", "encodedPassword")).thenReturn(true);
            assertThat(encoder.matches("password", "encodedPassword"), is(true));
        }

        @Test
        void onlyNullPasswordMatchesNullEncodedPassword() {
            assertThat(encoder.matches(null, null), is(true));
            assertThat(encoder.matches("", null), is(false));
        }
    }

    @Nested
    class WithMultipleDecodeOptions {

        @Test
        void encode() {
            when(mockPasswordEncoder.encode("password")).thenReturn("encodedPassword");
            assertThat(encoder.encode("password"), is("encodedPassword"));
        }

        @Test
        void doesNotMatchArbitraryPrefix() {
            assertThrowsWithMessageThat(
                    IllegalArgumentException.class,
                    () -> encoder.matches("password", "{prefix}encodedPassword"),
                    is("Password encoding {prefix} is not supported"));

            assertThrowsWithMessageThat(
                    IllegalArgumentException.class,
                    () -> encoder.matches("password", "{otherprefix}encodedPassword"),
                    is("Password encoding {otherprefix} is not supported"));

            verifyZeroInteractions(mockPasswordEncoder);
        }

        @Test
        void doesNotMatchInvalidPrefix() {
            assertThat(encoder.matches("password", "aaa{bcrypt}encodedPassword"), is(false));
            verify(mockPasswordEncoder).matches("password", "aaa{bcrypt}encodedPassword");
        }

        @Test
        void matchesBcryptPrefixOnly() {
            when(mockPasswordEncoder.matches("password", "encodedPassword")).thenReturn(true);
            assertThat(encoder.matches("password", "{bcrypt}encodedPassword"), is(true));
            verify(mockPasswordEncoder).matches("password", "encodedPassword");
        }
    }
}
