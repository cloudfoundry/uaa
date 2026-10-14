package org.cloudfoundry.identity.uaa.oauth.tls;

import com.google.re2j.Pattern;

import java.util.regex.PatternSyntaxException;

/** Shared registration and runtime limits for certificate OU claim patterns. */
public final class OuClaimPattern {
    private static final int MAX_SOURCE_LENGTH = 256;
    private static final int MAX_PROGRAM_SIZE = 4096;

    private OuClaimPattern() {
    }

    public static Pattern compile(String source) {
        if (source.length() > MAX_SOURCE_LENGTH) {
            throw new PatternSyntaxException("OU patterns are limited to 256 characters", source, -1);
        }
        // RE2 bounds matching, but nested counted groups can expand its compilation exponentially.
        // Reject counted groups before compiling. Literal/class counts and ordinary group * + ? remain valid.
        for (int i = 0; i + 2 < source.length(); i++) {
            if (source.charAt(i) == ')' && source.charAt(i + 1) == '{'
                    && source.charAt(i + 2) >= '0' && source.charAt(i + 2) <= '9') {
                throw new PatternSyntaxException("Counted repetitions of groups are not supported", source, i);
            }
        }
        final Pattern compiled;
        try {
            compiled = Pattern.compile(source);
        } catch (com.google.re2j.PatternSyntaxException e) {
            throw new PatternSyntaxException(e.getMessage(), source, -1);
        }
        if (compiled.programSize() > MAX_PROGRAM_SIZE) {
            throw new PatternSyntaxException("OU pattern exceeds the 4096 instruction limit", source, -1);
        }
        return compiled;
    }
}
