package org.cloudfoundry.identity.uaa.ratelimiting.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class IntUtilsTest {

    @Test
    void parsing() {
        assertEquals(1, IntUtils.parse("1", null));
        assertEquals(1, IntUtils.parseNoException("1", null));
        assertEquals(-1, IntUtils.parse(" ", -1));
        assertEquals(-1, IntUtils.parseNoException(" ", -1));
        assertEquals(-2, IntUtils.parse(null, -2));
        assertEquals(-2, IntUtils.parseNoException(null, -2));

        assertThrows(NumberFormatException.class, () -> IntUtils.parse("!Number", -1));
        assertEquals(-1, IntUtils.parseNoException("!Number", -1));
    }
}