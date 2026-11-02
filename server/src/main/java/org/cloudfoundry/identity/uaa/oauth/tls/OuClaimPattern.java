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
        rejectCountedGroups(source);
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

    /**
     * RE2 bounds matching, but nested counted groups can expand its compilation exponentially, so a
     * group closed by an unescaped {@code )} and followed by {@code {n} } is rejected before compiling.
     * Escaped and quoted characters and character-class members are literals, so counted literals such
     * as {@code \){2}} or {@code [)]{2}} and ordinary group {@code * + ?} remain valid.
     */
    private static void rejectCountedGroups(String source) {
        int length = source.length();
        boolean inClass = false;
        for (int i = 0; i < length; i++) {
            char c = source.charAt(i);
            if (c == '\\') {
                // RE2 honours \Q only outside a class; inside one it is an invalid escape.
                if (!inClass && i + 1 < length && source.charAt(i + 1) == 'Q') {
                    int end = source.indexOf("\\E", i + 2);
                    if (end < 0) {
                        return;
                    }
                    i = end + 1;
                } else {
                    i++;
                }
            } else if (inClass) {
                if (c == '[' && i + 1 < length && source.charAt(i + 1) == ':') {
                    int end = source.indexOf(":]", i + 2);
                    if (end >= 0) {
                        i = end + 1;
                    }
                } else if (c == ']') {
                    inClass = false;
                }
            } else if (c == '[') {
                inClass = true;
                if (i + 1 < length && source.charAt(i + 1) == '^') {
                    i++;
                }
                if (i + 1 < length && source.charAt(i + 1) == ']') {
                    i++;
                }
            } else if (c == ')' && i + 2 < length && source.charAt(i + 1) == '{'
                    && source.charAt(i + 2) >= '0' && source.charAt(i + 2) <= '9') {
                throw new PatternSyntaxException("Counted repetitions of groups are not supported", source, i);
            }
        }
    }
}
