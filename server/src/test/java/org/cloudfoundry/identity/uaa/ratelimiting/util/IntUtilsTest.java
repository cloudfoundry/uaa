package org.cloudfoundry.identity.uaa.ratelimiting.util;

import java.util.Arrays;
import java.util.List;
import java.util.function.Function;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class IntUtilsTest {
    private static final Integer[] JUST_NULLS = {null};
    private static final Integer[] VALUES = {5, 2, null, 7};

    @Test
    void parsing() {
        assertEquals( 1, IntUtils.parse( "1", null ) );
        assertEquals( 1, IntUtils.parseNoException( "1", null ) );
        assertEquals( -1, IntUtils.parse( " ", -1 ) );
        assertEquals( -1, IntUtils.parseNoException( " ", -1 ) );
        assertEquals( -2, IntUtils.parse( null, -2 ) );
        assertEquals( -2, IntUtils.parseNoException( null, -2 ) );

        assertThrows( NumberFormatException.class, () -> IntUtils.parse( "!Number", -1 ) );
    }

    @Test
    void minimumFrom() {
        assertEquals( 2, IntUtils.minimumFrom( Arrays.asList( VALUES ), Function.identity() ) );
        assertNull( IntUtils.minimumFrom( List.of( 5, 2, 7 ), null ) );
        assertNull( IntUtils.minimumFrom( null, Function.identity() ) );
        assertNull( IntUtils.minimumFrom( List.of(), Function.identity() ) );
        assertNull( IntUtils.minimumFrom( Arrays.asList( JUST_NULLS ), Function.identity() ) );
    }
}