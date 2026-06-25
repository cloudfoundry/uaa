package org.cloudfoundry.identity.uaa.util.beans;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pins the root {@code nonCachingPasswordEncoder} bean's empty-secret contract.
 * Spring Security 7's bcrypt encoder rejects empty rawPassword without an empty-aware wrapper.
 */
class PasswordEncoderConfigTest {

	@Test
	void nonCachingPasswordEncoderMatchesEmptySecretAgainstItsOwnEncoding() {
		PasswordEncoder encoder = new PasswordEncoderConfig().nonCachingPasswordEncoder();
		assertThat(encoder.matches("", encoder.encode(""))).isTrue();
	}
}
