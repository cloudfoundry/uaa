package org.cloudfoundry.identity.uaa.security.web;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class TimeLimitRegexMatcher {
    private static final long TIMEOUT_IN_MILLIS = 200L;

    public static Matcher matcher(Pattern pattern, CharSequence charSequence) {
        if (!(charSequence instanceof TimeLimitedCharSequence)) {
            charSequence = new TimeLimitedCharSequence(
                    charSequence,
                    TIMEOUT_IN_MILLIS,
                    pattern,
                    charSequence
            );
        }

        return pattern.matcher(charSequence);
    }

    public static class RegExTimeoutException extends RuntimeException {
        public RegExTimeoutException(String message) {
            super(message);
        }
    }

    private static class TimeLimitedCharSequence implements CharSequence {
        private final CharSequence charSequence;
        private final long timeoutInMillis;
        private final long timeoutTimestamp;
        private final Pattern pattern;
        private final CharSequence originalCharSequence;

        public TimeLimitedCharSequence(CharSequence charSequence, long timeoutInMillis, Pattern pattern, CharSequence originalCharSequence) {
            super();
            this.charSequence = charSequence;
            this.timeoutInMillis = timeoutInMillis;
            this.timeoutTimestamp = System.currentTimeMillis() + timeoutInMillis;
            this.pattern = pattern;
            this.originalCharSequence = originalCharSequence;
        }

        @Override
        public int length() {
            return charSequence.length();
        }

        @Override
        public char charAt(int index) {
            if(System.currentTimeMillis() > timeoutTimestamp) {
                throw new RegExTimeoutException("Regular expression timeout after "
                        + timeoutInMillis + "ms for [ "
                        + pattern.pattern() + " ] operating on [ "
                        + originalCharSequence + " ]");
            }
            return charSequence.charAt(index);
        }

        @Override
        public CharSequence subSequence(int start, int end) {
            return new TimeLimitedCharSequence(
                charSequence.subSequence(start, end), timeoutTimestamp - System.currentTimeMillis(), pattern, originalCharSequence
            );
        }

        public String toString() {
            return charSequence.toString();
        }
    }
}
