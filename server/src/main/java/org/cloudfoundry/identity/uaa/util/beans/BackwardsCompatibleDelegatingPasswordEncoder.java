package org.cloudfoundry.identity.uaa.util.beans;

import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Set;

public class BackwardsCompatibleDelegatingPasswordEncoder implements PasswordEncoder {

    private static final String OPTIONAL_BCRYPT_PREFIX = "bcrypt";
    private static final Set<String> BCRYPT_HASH_PREFIXES = Set.of("$2a$", "$2b$", "$2y$");
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

        String extracted = verifyPrefixAndExtractPassword(encodedPassword);
        // Spring Security 7's BCryptPasswordEncoder rejects empty rawPassword outright.
        // UAA legitimately stores BCrypt hashes of empty strings (e.g. the `cf` CLI client
        // has no secret), so we call BCrypt directly to preserve that behaviour.
        if (rawPassword.isEmpty() && isBcryptHash(extracted)) {
            try {
                return BCrypt.checkpw("", extracted);
            } catch (IllegalArgumentException _) {
                return false;
            }
        }

        return defaultPasswordEncoder.matches(rawPassword, extracted);
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

    private boolean isBcryptHash(String value) {
        return BCRYPT_HASH_PREFIXES.stream().anyMatch(value::startsWith);
    }
}
