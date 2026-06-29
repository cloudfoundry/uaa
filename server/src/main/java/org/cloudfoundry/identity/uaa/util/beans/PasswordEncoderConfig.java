package org.cloudfoundry.identity.uaa.util.beans;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class PasswordEncoderConfig {

    private static final Logger logger = LoggerFactory.getLogger(PasswordEncoderConfig.class);

    /**
     * Root password encoder bean for user passwords and client secrets.
     *
     * <p>Chain: {@link EmptyAwareDelegatingPasswordEncoder} →
     * {@link BackwardsCompatibleDelegatingPasswordEncoder} → {@link BCryptPasswordEncoder}.
     *
     * <p>{@link EmptyAwareDelegatingPasswordEncoder} must remain the outermost wrapper —
     * Spring Security 7's {@link BCryptPasswordEncoder} rejects empty {@code rawPassword} before
     * delegating, causing empty-secret clients (e.g. CF CLI) to be re-encoded on every startup,
     * invalidating tokens (UAA v79.0.0 regression).
     */
    @Bean
    public PasswordEncoder nonCachingPasswordEncoder() {
        logger.info("Building EmptyAwareDelegatingPasswordEncoder with BackwardsCompatibleDelegatingPasswordEncoder with {bcrypt} only");
        var defaultPasswordEncoder = new BCryptPasswordEncoder();
        var backwardsCompatibleDelegatingPasswordEncoder = new BackwardsCompatibleDelegatingPasswordEncoder(defaultPasswordEncoder);
        return new EmptyAwareDelegatingPasswordEncoder(backwardsCompatibleDelegatingPasswordEncoder);
    }
}
