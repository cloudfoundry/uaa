package org.cloudfoundry.identity.uaa.ratelimiting.internal.limitertracking;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.function.BiPredicate;
import java.util.stream.Stream;

import lombok.EqualsAndHashCode;
import lombok.RequiredArgsConstructor;
import org.cloudfoundry.identity.uaa.ratelimiting.core.config.LimiterMapping;

public class PathFragmentToLimiterMappings {
    private final BiPredicate<String, String> selector;
    private final PathFragmentToLimiterMapping[] ordered;
    private final IntPair[] lengthOrderedIndexes;

    /**
     * Constructor
     *
     * @param selector                        matching selector
     * @param pathFragmentWithLimiterMappings Collection of PathFragment and LimiterMappings pair
     */
    public PathFragmentToLimiterMappings(BiPredicate<String, String> selector,
            Collection<PathFragmentToLimiterMapping> pathFragmentWithLimiterMappings) {
        this.selector = selector;
        List<PathFragmentToLimiterMapping> mutable = new ArrayList<>( pathFragmentWithLimiterMappings );
        Collections.sort(mutable);
        ordered = mutable.toArray(new PathFragmentToLimiterMapping[0]);
        List<IntPair> orderedIndexes = new ArrayList<>( mutable.size() );
        IntPair prev = null;
        for (int i = 0; i < ordered.length; i++) {
            PathFragmentToLimiterMapping pftp = ordered[i];
            IntPair ip = new IntPair( pftp.getPathFragment().length(), i );
            if (!ip.equals(prev)) {
                orderedIndexes.add(prev = ip);
            }
        }
        lengthOrderedIndexes = orderedIndexes.toArray(new IntPair[0]);
    }

    // package friendly for Testing
    PathFragmentToLimiterMappings(BiPredicate<String, String> selector,
            PathFragmentToLimiterMapping... pathFragmentWithLimiterMappings) {
        this(selector, Arrays.asList(pathFragmentWithLimiterMappings));
    }

    public boolean isEmpty() {
        return 0 == count();
    }

    public int count() {
        return ordered.length;
    }

    public Stream<PathFragmentToLimiterMapping> stream() {
        return Arrays.stream(ordered);
    }

    public LimiterMapping get(String servletPath) {
        // Longest to Shortest pathFragments - finding the match that is longest!
        for (int i = findStartingOrderIndex(servletPath); i < ordered.length; i++) {
            PathFragmentToLimiterMapping pftp = ordered[i];
            if (selector.test(servletPath, pftp.getPathFragment())) {
                return pftp.getLimiterMapping();
            }
        }
        return null;
    }

    private int findStartingOrderIndex(String servletPath) {
        int maxLength = servletPath.length();
        for (IntPair pair : lengthOrderedIndexes) {
            if (pair.length <= maxLength) {
                return pair.index;
            }
        }
        return Integer.MAX_VALUE;
    }

    @RequiredArgsConstructor
    @EqualsAndHashCode
    private static class IntPair {
        public final int length;
        public final int index;
    }
}
