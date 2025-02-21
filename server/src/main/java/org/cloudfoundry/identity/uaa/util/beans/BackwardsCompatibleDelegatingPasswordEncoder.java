package org.cloudfoundry.identity.uaa.util.beans;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

public class BackwardsCompatibleDelegatingPasswordEncoder implements PasswordEncoder {

    private static final String OPTIONAL_BCRYPT_PREFIX = "bcrypt";
    private final BCryptPasswordEncoder defaultPasswordEncoder;
    private static final Logger slogger = LoggerFactory.getLogger(BackwardsCompatibleDelegatingPasswordEncoder.class);

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

        if (rawPassword.length() > 72) {
            slogger.error("BCrypt password match cannot exceed 72 characters.");
            return false;
        }

        return defaultPasswordEncoder.matches(rawPassword, verifyPrefixAndExtractPassword(encodedPassword));
    }

    private String verifyPrefixAndExtractPassword(String encodedPassword) {
        int startIndex = encodedPassword.indexOf("{");
        int endIndex = encodedPassword.indexOf("}");

        if (startIndex != 0 || endIndex == -1) {
            return encodedPassword;
        }

        String prefix = encodedPassword.substring(startIndex + 1, endIndex);
        if (!prefix.equals(OPTIONAL_BCRYPT_PREFIX)) {
            throw new IllegalArgumentException("Password encoding {%s} is not supported".formatted(prefix));
        }
        return encodedPassword.substring(endIndex + 1);
    }
}
