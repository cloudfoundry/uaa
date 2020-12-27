package org.cloudfoundry.identity.uaa;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;


import org.cloudfoundry.identity.statsd.UaaMetricsEmitter;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;

class UaaStatsdConfigurationSpringTest {

    @Nested
    @ExtendWith(SpringExtension.class)
    @ContextConfiguration(classes = UaaStatsdConfiguration.class)
    @TestPropertySource(properties = "statsd.enabled=true")
    class WithStatsdEnabled {
        @Test
        void statsdIsNotAvailable(@Autowired(required = false) UaaMetricsEmitter statsDClientWrapper) {
            assertNotNull(statsDClientWrapper, "statsDClientWrapper must be available");
        }
    }

    @Nested
    @ExtendWith(SpringExtension.class)
    @ContextConfiguration(classes = UaaStatsdConfiguration.class)
    @TestPropertySource(properties = "statsd.enabled=baz")
    class WithStatsdExplicitlyDisabled {
        @Test
        void statsdIsNotAvailable(@Autowired(required = false) UaaMetricsEmitter statsDClientWrapper) {
            assertNull(statsDClientWrapper, "statsDClientWrapper must not be available");
        }
    }

    @Nested
    @ExtendWith(SpringExtension.class)
    @ContextConfiguration(classes = UaaStatsdConfiguration.class)
    class WithStatsdDisabledByDefault {
        @Test
        void statsdIsNotAvailable(@Autowired(required = false) UaaMetricsEmitter statsDClientWrapper) {
            assertNull(statsDClientWrapper, "statsDClientWrapper must not be available");
        }
    }

}