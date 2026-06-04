package org.cloudfoundry.identity.uaa.authentication;

import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Set;

/**
 * Wraps a {@link PasswordEncoder} to allow empty raw passwords.
 * Spring Security 7 {@code AbstractValidatingPasswordEncoder} returns {@code false} from {@code matches()}
 * when {@code rawPassword.length() == 0}. UAA legitimately supports clients with no secret (e.g. CF CLI),
 * whose stored hash is the encoding of an empty string.
 */
class EmptyPasswordAwareEncoder implements PasswordEncoder {

    private static final String NOOP_PREFIX = "{noop}";
    private static final String BCRYPT_PREFIX = "{bcrypt}";
    private static final Set<String> BCRYPT_HASH_PREFIXES = Set.of("$2a$", "$2b$", "$2y$");

    private final PasswordEncoder delegate;

    EmptyPasswordAwareEncoder(PasswordEncoder delegate) {
        this.delegate = delegate;
    }

    @Override
    public String encode(CharSequence rawPassword) {
        return delegate.encode(rawPassword);
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        if (rawPassword == null) {
            return false;
        }
        if (rawPassword.isEmpty()) {
            return emptyPasswordMatchesStoredHash(encodedPassword);
        }

        return delegate.matches(rawPassword, encodedPassword);
    }

    private boolean emptyPasswordMatchesStoredHash(String encodedPassword) {
        if (encodedPassword == null) {
            return false;
        }

        if (NOOP_PREFIX.equals(encodedPassword)) {
            return true;
        }

        String extracted = extractPasswordValue(encodedPassword);
        return isBcryptHash(extracted) && bcryptMatchesEmpty(extracted);
    }

    private String extractPasswordValue(String encodedPassword) {
        if (encodedPassword.startsWith(BCRYPT_PREFIX)) {
            return encodedPassword.substring(BCRYPT_PREFIX.length());
        }

        return encodedPassword;
    }

    private boolean isBcryptHash(String value) {
        return BCRYPT_HASH_PREFIXES.stream().anyMatch(value::startsWith);
    }

    private boolean bcryptMatchesEmpty(String hash) {
        try {
            return BCrypt.checkpw("", hash);
        } catch (IllegalArgumentException _) {
            return false;
        }
    }
}
