package org.cloudfoundry.identity.uaa.util;

import com.google.re2j.Pattern;
import com.google.re2j.PatternSyntaxException;

import java.util.Collection;
import java.util.regex.Matcher;

/**
 * Compiles tenant- or operator-supplied regular expressions with RE2/J and limits how much work a pattern can cause.
 * <p>
 * RE2/J matches in time proportional to the input length times the compiled program size, and has no lookahead,
 * backreferences or other constructs that need backtracking. It does not, however, limit the cost of compiling a
 * pattern: deeply nested counted repetitions such as {@code ((a{1000}){1000}){1000}} exhaust memory, and very long
 * patterns take a long time to compile. These limits keep both compile cost and match cost bounded.
 * <p>
 * Every rejection is reported as a {@link PatternSyntaxException}, so callers can treat a pattern that is too costly
 * the same way as one that is invalid.
 */
public final class BoundedRegex {

    /** Longest pattern accepted, in characters. */
    public static final int MAX_PATTERN_LENGTH = 512;
    /** Largest product of all counted repetition bounds ({@code {n}}, {@code {n,m}}) in one pattern. */
    public static final int MAX_REPETITION_PRODUCT = 1000;
    /**
     * Largest pattern length multiplied by the repetition product. A repeated group is expanded when compiled, so
     * this bounds the memory a pattern can use before its compiled program size is known.
     */
    public static final int MAX_COMPILE_ESTIMATE = 50_000;
    /** Largest compiled program, in RE2/J instructions, for one pattern. */
    public static final int MAX_PROGRAM_SIZE = 2000;
    /** Most patterns accepted in one list. */
    public static final int MAX_PATTERNS = 32;
    /** Largest total compiled program size for one list of patterns. */
    public static final int MAX_TOTAL_PROGRAM_SIZE = 8192;

    // Deliberately matches inside character classes and escapes too: over-counting only rejects more patterns.
    private static final java.util.regex.Pattern COUNTED_REPETITION =
            java.util.regex.Pattern.compile("\\{(\\d{1,9})(?:,(\\d{0,9}))?}");

    private BoundedRegex() {
    }

    public static Pattern compile(String regex) {
        if (regex == null) {
            throw new PatternSyntaxException("pattern must not be null", "null");
        }
        if (regex.length() > MAX_PATTERN_LENGTH) {
            throw new PatternSyntaxException("pattern is longer than %d characters".formatted(MAX_PATTERN_LENGTH),
                    regex.substring(0, 32) + "...");
        }
        long product = repetitionProduct(regex);
        if (product > MAX_REPETITION_PRODUCT) {
            throw new PatternSyntaxException(
                    "counted repetitions multiply to more than %d".formatted(MAX_REPETITION_PRODUCT), regex);
        }
        if (regex.length() * product > MAX_COMPILE_ESTIMATE) {
            throw new PatternSyntaxException("pattern is too large for its repetition counts", regex);
        }
        Pattern compiled = Pattern.compile(regex);
        if (compiled.programSize() > MAX_PROGRAM_SIZE) {
            throw new PatternSyntaxException("pattern compiles to more than %d instructions".formatted(MAX_PROGRAM_SIZE), regex);
        }
        return compiled;
    }

    /** True when a list holds few enough patterns, with a small enough total program, to evaluate on every request. */
    public static boolean withinListLimits(Collection<Pattern> patterns) {
        if (patterns.size() > MAX_PATTERNS) {
            return false;
        }
        long total = 0;
        for (Pattern pattern : patterns) {
            total += pattern.programSize();
        }
        return total <= MAX_TOTAL_PROGRAM_SIZE;
    }

    private static long repetitionProduct(String regex) {
        long product = 1;
        Matcher matcher = COUNTED_REPETITION.matcher(regex);
        while (matcher.find()) {
            String upper = matcher.group(2) != null && !matcher.group(2).isEmpty() ? matcher.group(2) : matcher.group(1);
            product = Math.min(product * Math.max(1, Long.parseLong(upper)), MAX_REPETITION_PRODUCT + 1L);
        }
        return product;
    }
}
