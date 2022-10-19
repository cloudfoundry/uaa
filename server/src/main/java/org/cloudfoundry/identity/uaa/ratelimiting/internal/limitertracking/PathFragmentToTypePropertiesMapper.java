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

public class PathFragmentToTypePropertiesMapper {
    private final BiPredicate<String, String> selector;
    private final PathFragmentToTypeProperties[] ordered;
    private final IntPair[] lengthOrderedIndexes;

    /**
     * Constructor
     *
     * @param selector                   matching selector
     * @param pathFragmentWithProperties Collection of PathFragment and TypeProperties pair
     */
    public PathFragmentToTypePropertiesMapper( BiPredicate<String, String> selector,
                                               Collection<PathFragmentToTypeProperties> pathFragmentWithProperties ) {
        this.selector = selector;
        List<PathFragmentToTypeProperties> mutable = new ArrayList<>( pathFragmentWithProperties );
        Collections.sort( mutable );
        ordered = mutable.toArray( new PathFragmentToTypeProperties[0] );
        List<IntPair> orderedIndexes = new ArrayList<>( mutable.size() );
        IntPair prev = null;
        for ( int i = 0; i < ordered.length; i++ ) {
            PathFragmentToTypeProperties pftp = ordered[i];
            IntPair ip = new IntPair( pftp.getPathFragment().length(), i );
            if ( !ip.equals( prev ) ) {
                orderedIndexes.add( prev = ip );
            }
        }
        lengthOrderedIndexes = orderedIndexes.toArray( new IntPair[0] );
    }

    // package friendly for Testing
    PathFragmentToTypePropertiesMapper( BiPredicate<String, String> selector,
                                        PathFragmentToTypeProperties... pathFragmentWithProperties ) {
        this( selector, Arrays.asList( pathFragmentWithProperties ) );
    }

    public boolean isEmpty() {
        return (0 == count());
    }

    public int count() {
        return ordered.length;
    }

    public Stream<PathFragmentToTypeProperties> stream() {
        return Arrays.stream( ordered );
    }

    public LimiterMapping get( String servletPath ) {
        // Longest to Shortest pathFragments - finding the match that is longest!
        for ( int i = findStartingOrderIndex( servletPath ); i < ordered.length; i++ ) {
            PathFragmentToTypeProperties pftp = ordered[i];
            if ( selector.test( servletPath, pftp.getPathFragment() ) ) {
                return pftp.getProperties();
            }
        }
        return null;
    }

    private int findStartingOrderIndex( String servletPath ) {
        int maxLength = servletPath.length();
        for ( IntPair pair : lengthOrderedIndexes ) {
            if ( pair.length <= maxLength ) {
                return pair.index;
            }
        }
        return Integer.MAX_VALUE;
    }

    @RequiredArgsConstructor
    @EqualsAndHashCode
    private static class IntPair {
        public final int length, index;
    }
}
