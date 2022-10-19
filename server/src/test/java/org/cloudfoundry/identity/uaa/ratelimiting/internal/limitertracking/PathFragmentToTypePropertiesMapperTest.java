package org.cloudfoundry.identity.uaa.ratelimiting.internal.limitertracking;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.function.BiPredicate;
import java.util.stream.Collectors;

import org.cloudfoundry.identity.uaa.ratelimiting.core.config.LimiterMapping;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PathFragmentToTypePropertiesMapperTest {

    private PathFragmentToTypePropertiesMapper mapper;
    private Selector selector;

    @Test
    void noProperties() {
        mapper = new PathFragmentToTypePropertiesMapper( String::contains );

        assertTrue( mapper.isEmpty() );
        assertEquals( 0, mapper.count() );
        assertEquals( List.of(), streamToPathFragments() );

        assertNull( mapper.get( "significantOther/Wilma/of/Fred" ) );
    }

    @Test
    void fewProperties() {
        PathFragmentToTypeProperties fred = pftp( "Fred" );
        PathFragmentToTypeProperties pebbles = pftp( "Pebbles" );
        PathFragmentToTypeProperties wilma = pftp( "Wilma" );

        mapper = new PathFragmentToTypePropertiesMapper( String::contains, fred, pebbles, wilma );

        assertFalse( mapper.isEmpty() );
        assertEquals( 3, mapper.count() );
        assertEquals( List.of( pebbles, wilma, fred ), streamToPathFragments() );

        assertEquals( wilma.getProperties(), mapper.get( "significantOther/Wilma/of/Fred" ) );
    }

    @Test
    void getCompares() {
        selector = new Selector();
        List<PathFragmentToTypeProperties> pftps = new ArrayList<>();
        for ( int i = 1; i <= 50; i++ ) {
            addTo( pftps, makePath( 'A', i ) );
            addTo( pftps, makePath( 'B', i ) );
        }
        mapper = new PathFragmentToTypePropertiesMapper( selector, pftps );

        assertEquals( 2, check( false, "X" ) );
        assertEquals( 50, check( false, makePath( 'X', 25 ) ) );
        assertEquals( 100, check( false, makePath( 'X', 50 ) ) );
        assertEquals( 2, check( true, makePath( 'B', 25 ) ) );
    }

    private int check( boolean expectedFound, String servletPath ) {
        selector.calls = 0;
        Instant start = Instant.now();
        LimiterMapping found = mapper.get( servletPath );
        int calls = selector.calls;
        System.out.println( Duration.between( start, Instant.now() ).toNanos() + "ns: " + calls + " -> " + servletPath );
        if ( expectedFound ) {
            assertNotNull( found );
        } else {
            assertNull( found );
        }
        return calls;
    }

    private void addTo( List<PathFragmentToTypeProperties> collection, String pathFragmentAndName ) {
        collection.add( pftp( pathFragmentAndName ) );
    }

    private static String makePath( char letter, int count ) {
        StringBuilder sb = new StringBuilder( count );
        while ( 0 < count-- ) {
            sb.append( letter );
        }
        return sb.toString();
    }

    private static class Selector implements BiPredicate<String, String> {
        int calls;

        @Override
        public boolean test( String servletPath, String pathFragment ) {
            calls++;
            return servletPath.equals( pathFragment ); // using equals just for testing!
        }
    }

    private static PathFragmentToTypeProperties pftp( String pathFragmentAndName ) {
        return new PathFragmentToTypeProperties( pathFragmentAndName,
                                                 LimiterMapping.builder()
                                                         .name( pathFragmentAndName )
                                                         .pathSelector( "contains:" + pathFragmentAndName )
                                                         .global( "1r/s" )
                                                         .build() );
    }

    private List<PathFragmentToTypeProperties> streamToPathFragments() {
        return mapper.stream().collect( Collectors.toList() );
    }
}