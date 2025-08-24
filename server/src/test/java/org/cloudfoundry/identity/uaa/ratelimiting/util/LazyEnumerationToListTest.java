package org.cloudfoundry.identity.uaa.ratelimiting.util;

import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class LazyEnumerationToListTest {
    private static final List<Integer> SOURCE = List.of(3, 1, 4, 1, 5, 9);

    private final Enumeration<Integer> enumeration = Collections.enumeration(SOURCE);

    @Test
    void getSupplier() {
        checkNull(new LazyEnumerationToList<>(() -> null));
        checkNonNull(new LazyEnumerationToList<>(() -> enumeration));
    }

    @Test
    void getEnumeration() {
        checkNull(new LazyEnumerationToList<>((Enumeration<Integer>) null));
        checkNonNull(new LazyEnumerationToList<>(enumeration));
    }

    private void checkNull(LazyEnumerationToList<Integer> el) {
        assertThat(el).isNotNull();
        assertThat(el.get()).isEqualTo(Collections.emptyList());
        assertThat(el.hasValue()).isFalse();
    }

    private void checkNonNull(LazyEnumerationToList<Integer> el) {
        assertThat(el).isNotNull();
        assertThat(el.get()).isEqualTo(SOURCE);
        assertThat(el.hasValue()).isTrue();
    }
}