package org.cloudfoundry.identity.uaa.ratelimiting.util;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SingletonTest {
    private static final String VALUE = "Fred lives here";

    private final Singleton<String> singleton = new Singleton<>(() -> VALUE);

    @Test
    void getInstance() {
        String value1 = singleton.getInstance();
        String value2 = singleton.getInstance();

        assertThat(value1).isSameAs(VALUE);
        assertThat(value2).isSameAs(value1);
    }
}