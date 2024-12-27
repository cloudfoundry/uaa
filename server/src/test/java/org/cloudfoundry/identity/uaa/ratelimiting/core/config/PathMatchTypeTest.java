package org.cloudfoundry.identity.uaa.ratelimiting.core.config;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

@SuppressWarnings("SameParameterValue")
class PathMatchTypeTest {

    @Test
    void options() {
        assertEquals("All, Other, Contains, StartsWith, or Equals", PathMatchType.options());
    }

    @Test
    void pathUnacceptable() {
        checkStartsWithSlash(PathMatchType.Equals);
        checkStartsWithSlash(PathMatchType.StartsWith);
        checkNotEmpty(PathMatchType.Contains);
        checkEmpty(PathMatchType.Other);
        checkEmpty(PathMatchType.All);
    }

    private void checkStartsWithSlash(PathMatchType type) {
        assertNull(type.pathUnacceptable("/stuff"), type + ":/stuff");
        assertEquals("must start with a slash ('/')", type.pathUnacceptable("No-slash"), type + ":No-slash");
    }

    private void checkNotEmpty(PathMatchType type) {
        assertNull(type.pathUnacceptable("stuff"), type + ":stuff");
        assertEquals("must not be empty", type.pathUnacceptable(""), type + ":");
    }

    private void checkEmpty(PathMatchType type) {
        assertNull(type.pathUnacceptable(""), type + ":");
        assertEquals("must be empty", type.pathUnacceptable("Not-empty"), type + ":Not-empty");
    }
}