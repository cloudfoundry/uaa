package org.cloudfoundry.identity.uaa.authentication;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;

class EmptyPasswordAwareEncoderTest {

    private final PasswordEncoder bcrypt = new BCryptPasswordEncoder();
    private final EmptyPasswordAwareEncoder encoder = new EmptyPasswordAwareEncoder(bcrypt);

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
}
