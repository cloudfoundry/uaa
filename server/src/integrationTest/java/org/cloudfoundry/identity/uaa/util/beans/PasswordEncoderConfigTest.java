package org.cloudfoundry.identity.uaa.util.beans;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pins that the production {@code nonCachingPasswordEncoder} bean wraps with
 * {@link EmptyAwareDelegatingPasswordEncoder}. Runs in the {@code integrationTest} source set
 * so {@link PasswordEncoderConfig} is the production class, not the test-scope shadow.
 */
class PasswordEncoderConfigTest {

    @Test
    void nonCachingPasswordEncoderMatchesEmptySecretAgainstItsOwnEncoding() {
        PasswordEncoder encoder = new PasswordEncoderConfig().nonCachingPasswordEncoder();
        assertThat(encoder.matches("", encoder.encode(""))).isTrue();
    }
}
