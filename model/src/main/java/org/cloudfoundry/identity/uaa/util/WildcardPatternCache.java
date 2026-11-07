package org.cloudfoundry.identity.uaa.util;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.UnaryOperator;
import java.util.regex.Pattern;

/**
 * Caches compiled wildcard {@link Pattern}s so they are not rebuilt on every evaluation.
 * <p>
 * Callers on request paths typically hold a configuration object that is reconstructed per
 * request, so the compiled pattern cannot be cached on the caller. Keying by the wildcard
 * string instead keeps the compilation cost to the first use. The cache is bounded so a large
 * number of distinct patterns cannot grow it without limit.
 */
public final class WildcardPatternCache {

    private static final int CACHE_SIZE = 512;

    // Keyed by the generated regular expression rather than the wildcard string, so that two
    // replacement strategies applied to the same wildcard cannot return each other's pattern.
    private static final Map<String, Pattern> CACHE = Collections.synchronizedMap(
            new LinkedHashMap<>(64, 0.75f, true) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<String, Pattern> eldest) {
                    return size() > CACHE_SIZE;
                }
            });

    private WildcardPatternCache() {
    }

    /**
     * Compiles the wildcard string with the given replacement strategy, returning a cached
     * instance when the same expression was compiled before.
     */
    public static Pattern compile(String wildcard, UnaryOperator<String> replace) {
        return CACHE.computeIfAbsent(replace.apply(wildcard), Pattern::compile);
    }
}
