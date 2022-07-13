package org.cloudfoundry.identity.uaa.ratelimiting.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class SingletonTest {
    private static final String VALUE = "Fred lives here";

    private final Singleton<String> singleton = new Singleton<>( () -> VALUE );

    @Test
    void getInstance() {
        String value1 = singleton.getInstance();
        String value2 = singleton.getInstance();

        assertSame( value1, VALUE );
        assertSame( value1, value2 );
    }
}