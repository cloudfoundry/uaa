package org.cloudfoundry.identity.uaa.util.beans;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

public class BackwardsCompatibleDelegatingPasswordEncoder implements PasswordEncoder {

    private static final String NOOP_PREFIX = "{noop}";
    private static final String BCRYPT_PREFIX = "{bcrypt}";
    private final BCryptPasswordEncoder defaultPasswordEncoder;

    public BackwardsCompatibleDelegatingPasswordEncoder(final BCryptPasswordEncoder defaultPasswordEncoder) {
        this.defaultPasswordEncoder = defaultPasswordEncoder;
    }

    @Override
    public String encode(CharSequence rawPassword) {
        return defaultPasswordEncoder.encode(rawPassword);
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        if (rawPassword == null && encodedPassword == null) {
            return true;
        }

        if (rawPassword == null || encodedPassword == null) {
            return false;
        }

        // Handle {noop} prefixed passwords with direct comparison
        if (encodedPassword.startsWith(NOOP_PREFIX)) {
            String storedPassword = encodedPassword.substring(NOOP_PREFIX.length());
            return rawPassword.toString().equals(storedPassword);
        }

        return defaultPasswordEncoder.matches(rawPassword, verifyPrefixAndExtractPassword(encodedPassword));
    }

    private String verifyPrefixAndExtractPassword(String encodedPassword) {
        int startIndex = encodedPassword.indexOf("{");
        int endIndex = encodedPassword.indexOf("}");

        if (startIndex != 0 || endIndex == -1) {
            return encodedPassword;
        }

        String prefix = encodedPassword.substring(startIndex, endIndex + 1);
        if (!prefix.equals(BCRYPT_PREFIX) && !prefix.equals(NOOP_PREFIX)) {
            throw new IllegalArgumentException("Password encoding %s is not supported".formatted(prefix));
        }
        return encodedPassword.substring(endIndex + 1);
    }
}
