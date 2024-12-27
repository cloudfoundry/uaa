package org.cloudfoundry.identity.uaa.ratelimiting.util;

import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class LazyEnumerationToListTest {
    private static final List<Integer> SOURCE = List.of(3, 1, 4, 1, 5, 9);

    private final Enumeration<Integer> enumeration = Collections.enumeration(SOURCE);

    @Test
    void getSupplier() {
        checkNull(new LazyEnumerationToList<>( () -> null ));
        checkNonNull(new LazyEnumerationToList<>( () -> enumeration ));
    }

    @Test
    void getEnumeration() {
        checkNull(new LazyEnumerationToList<>( (Enumeration<Integer>) null ));
        checkNonNull(new LazyEnumerationToList<>( enumeration ));
    }

    private void checkNull(LazyEnumerationToList<Integer> el) {
        assertNotNull(el);
        assertEquals(Collections.emptyList(), el.get());
        assertFalse(el.hasValue());
    }

    private void checkNonNull(LazyEnumerationToList<Integer> el) {
        assertNotNull(el);
        assertEquals(SOURCE, el.get());
        assertTrue(el.hasValue());
    }
}