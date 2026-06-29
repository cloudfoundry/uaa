package org.cloudfoundry.identity.uaa.util.beans;

import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Set;

import static org.cloudfoundry.identity.uaa.util.beans.SecureStringComparison.constantTimeEquals;

/**
 * Wraps a {@link PasswordEncoder} to allow empty raw passwords.
 * Spring Security 7 {@code AbstractValidatingPasswordEncoder} returns {@code false} from {@code matches()}
 * when {@code rawPassword.length() == 0}. UAA legitimately supports clients with no secret (e.g. CF CLI).
 *
 * <p>For an empty raw password, {@link #encode(CharSequence)} returns the literal {@code {noop}} sentinel
 * (stable across restarts), while {@link #matches(CharSequence, String)} accepts either that {@code {noop}}
 * sentinel or a legacy bcrypt hash of the empty string.
 */
public class EmptyAwareDelegatingPasswordEncoder implements PasswordEncoder {

    private static final String NOOP_PREFIX = "{noop}";
    private static final String BCRYPT_PREFIX = "{bcrypt}";
    private static final Set<String> BCRYPT_HASH_PREFIXES = Set.of("$2a$", "$2b$", "$2y$");

    private final PasswordEncoder delegate;

    public EmptyAwareDelegatingPasswordEncoder(PasswordEncoder delegate) {
        this.delegate = delegate;
    }

    @Override
    public String encode(CharSequence rawPassword) {
        // For empty passwords, use noop encoding to maintain compatibility with legacy behavior
        if (rawPassword != null && rawPassword.isEmpty()) {
            return NOOP_PREFIX;
        }
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

        if (constantTimeEquals(NOOP_PREFIX, encodedPassword)) {
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
