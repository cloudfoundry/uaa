package org.cloudfoundry.identity.uaa.ratelimiting.util;

import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class BoolUtilsTest {
    private static final Boolean[] JUST_NULLS = {null};
    private static final Boolean[] VALUES = {false, false, null, true, false};

    @Test
    void anyTrue() {
        assertTrue( BoolUtils.anyTrue( Arrays.asList( VALUES ), Boolean::booleanValue ) );
        assertFalse( BoolUtils.anyTrue( List.of( false ), Boolean::booleanValue ) );
        assertNull( BoolUtils.anyTrue( Arrays.asList( VALUES ), null ) );
        assertNull( BoolUtils.anyTrue( null, Boolean::booleanValue ) );
        assertNull( BoolUtils.anyTrue( List.of(), Boolean::booleanValue ) );
        assertNull( BoolUtils.anyTrue( Arrays.asList( JUST_NULLS ), Boolean::booleanValue ) );
    }
}