package org.cloudfoundry.identity.uaa.authentication;

import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Wraps a {@link PasswordEncoder} to allow empty raw passwords.
 * Spring Security 7 {@code AbstractValidatingPasswordEncoder} returns {@code false} from {@code matches()}
 * when {@code rawPassword.length() == 0}. UAA legitimately supports clients with no secret (e.g. CF CLI),
 * whose stored hash is the encoding of an empty string.
 */
class EmptyPasswordAwareEncoder implements PasswordEncoder {

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
        if (rawPassword != null && rawPassword.isEmpty()) {
            return emptyPasswordMatchesStoredHash(encodedPassword);
        }

        return delegate.matches(rawPassword, encodedPassword);
    }

    private boolean emptyPasswordMatchesStoredHash(String encodedPassword) {
        if (encodedPassword == null) {
            return false;
        }

        if ("{noop}".equals(encodedPassword)) {
            return true;
        }

        String extracted = extractPasswordValue(encodedPassword);
        return isBcryptHash(extracted) && bcryptMatchesEmpty(extracted);
    }

    private String extractPasswordValue(String encodedPassword) {
        int start = encodedPassword.indexOf('{');
        int end = encodedPassword.indexOf('}');

        if (start == 0 && end > 0) {
            return encodedPassword.substring(end + 1);
        }

        return encodedPassword;
    }

    private boolean isBcryptHash(String value) {
        return value.startsWith("$2a$") || value.startsWith("$2b$") || value.startsWith("$2y$");
    }

    private boolean bcryptMatchesEmpty(String hash) {
        try {
            return BCrypt.checkpw("", hash);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
}
