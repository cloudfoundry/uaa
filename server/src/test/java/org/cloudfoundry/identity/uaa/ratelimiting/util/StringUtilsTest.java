package org.cloudfoundry.identity.uaa.ratelimiting.util;

import java.util.List;

import org.assertj.core.util.Arrays;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class StringUtilsTest {
    private static final List<Object> EMPTY = List.of();
    private static final List<Object> JUST_NULLS = Arrays.asList( new Object[]{null} );
    private static final List<Object> VALUES = Arrays.asList( new Object[]{5, 2, null, 7, "Martin Fowler"} );

    @Test
    void normalize() {
        check( "Uncle Bob" ); // no changes if not empty and no leading or trailing spaces
        check( "  Sir Tony Hoare  ", "Sir Tony Hoare" ); // not empty, but leading and trailing spaces removed
        check( null, "", null );
        check( "  ", "", null );
    }

    @SuppressWarnings("SameParameterValue")
    private void check( String inputAndOutput ) {
        check( inputAndOutput, inputAndOutput );
    }

    private void check( String input, String normalizeSame ) {
        check( input, normalizeSame, normalizeSame );
    }

    private void check( String input, String normalizeToEmpty, String normalizeToNull ) {
        assertEquals( normalizeToEmpty, StringUtils.normalizeToEmpty( input ) );
        assertEquals( normalizeToNull, StringUtils.normalizeToNull( input ) );
    }

    @Test
    void options() {
        String expectedEMPTY = "";
        String expectedJUST_NULLS = "null";
        String expectedVALUES = "'Martin Fowler', 7, null, 2, or 5"; // Note in reverse order

        assertEquals( expectedEMPTY, StringUtils.options( EMPTY ), "EMPTY" );
        assertEquals( expectedJUST_NULLS, StringUtils.options( JUST_NULLS ), "JUST_NULLS" );
        assertEquals( expectedVALUES, StringUtils.options( VALUES ), "VALUES" );

        String oneLabel = "type";
        assertEquals( "no " + oneLabel + "s" + expectedEMPTY, StringUtils.options( oneLabel, EMPTY ), "EMPTY 1label" );
        assertEquals( "the " + oneLabel + " is: " + expectedJUST_NULLS, StringUtils.options( oneLabel, JUST_NULLS ), "JUST_NULLS 1label" );
        assertEquals( "the " + oneLabel + "s are: " + expectedVALUES, StringUtils.options( oneLabel, VALUES ), "VALUES 1label" );

        String labelSingular = "child";
        String labelPlural = "children";
        assertEquals( "no " + labelPlural + expectedEMPTY, StringUtils.options( labelSingular, labelPlural, EMPTY ), "EMPTY 2labels" );
        assertEquals( "the " + labelSingular + " is: " + expectedJUST_NULLS, StringUtils.options( labelSingular, labelPlural, JUST_NULLS ), "JUST_NULLS 2labels" );
        assertEquals( "the " + labelPlural + " are: " + expectedVALUES, StringUtils.options( labelSingular, labelPlural, VALUES ), "VALUES 2labels" );
    }
}