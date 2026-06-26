package org.cloudfoundry.identity.uaa.oauth.beans;

import org.cloudfoundry.identity.uaa.util.CachingPasswordEncoder;
import org.cloudfoundry.identity.uaa.util.beans.PasswordEncoderConfig;
import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pins that the {@code cachingPasswordEncoder} bean also handles empty secrets correctly.
 * Runs in the {@code prodWiringTest} source set so {@link PasswordEncoderConfig} is the
 * production class, not the test-scope shadow.
 */
class OauthEndpointBeanConfigurationTest {

    @Test
    void cachingPasswordEncoderMatchesEmptySecretAgainstItsOwnEncoding() throws NoSuchAlgorithmException {
        CachingPasswordEncoder encoder = new CachingPasswordEncoder(new PasswordEncoderConfig().nonCachingPasswordEncoder());
        assertThat(encoder.matches("", encoder.encode(""))).isTrue();
    }
}
