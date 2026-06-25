package org.cloudfoundry.identity.uaa.oauth.beans;

import org.cloudfoundry.identity.uaa.util.CachingPasswordEncoder;
import org.cloudfoundry.identity.uaa.util.beans.PasswordEncoderConfig;
import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pins the cachingPasswordEncoder bean's empty-secret contract; the cache is a
 * pass-through, so this is the same Spring Security 7 regression as
 * {@link org.cloudfoundry.identity.uaa.util.beans.PasswordEncoderConfig}'s nonCachingPasswordEncoder,
 * applied to the bean wired into OauthEndpointBeanConfiguration.
 */
class OauthEndpointBeanConfigurationTest {

    @Test
    void cachingPasswordEncoderMatchesEmptySecretAgainstItsOwnEncoding() throws NoSuchAlgorithmException {
        CachingPasswordEncoder encoder = new CachingPasswordEncoder(new PasswordEncoderConfig().nonCachingPasswordEncoder());

        assertThat(encoder.matches("", encoder.encode(""))).isTrue();
    }
}
