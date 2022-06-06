package org.cloudfoundry.identity.uaa.ratelimiting.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class NullTest {
    private static final Object[] EMPTY = {};
    private static final Object[] JUST_NULLS = {null};
    private static final Object[] VALUES = {5, 2, null, 7, "Martin Fowler"};

    @Test
    void countNonNull() {
        assertEquals( 0, Null.countNonNull( EMPTY ), "EMPTY" );
        assertEquals( 0, Null.countNonNull( JUST_NULLS ), "JUST_NULLS" );
        assertEquals( 4, Null.countNonNull( VALUES ), "VALUES" );
    }

    @Test
    void errorOn() {
        assertEquals( 1, Null.errorOn( "whatever", 1 ) );

        Object o;
        try {
            o = Null.errorOn( "thing", null );
            assertNotNull( o );
        }
        catch ( Error e ) {
            assertEquals( "No 'thing' provided -- coding error", e.getMessage() );
        }
    }

    @Test
    void defaultOn() {
        assertEquals( "whatever", Null.defaultOn( "whatever", "!whatever" ) );
        assertEquals( "!whatever", Null.defaultOn( null, "!whatever" ) );
    }
}