package org.cloudfoundry.identity.uaa;

import org.cloudfoundry.identity.statsd.UaaMetricsEmitter;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;

import static org.assertj.core.api.Assertions.assertThat;

class UaaStatsdConfigurationSpringTest {

    @Nested
    @SpringJUnitConfig(classes = UaaStatsdConfiguration.class)
    @TestPropertySource(properties = "statsd.enabled=true")
    class WithStatsdEnabled {
        @Test
        void statsdIsNotAvailable(@Autowired(required = false) UaaMetricsEmitter statsDClientWrapper) {
            assertThat(statsDClientWrapper).as("statsDClientWrapper must be available").isNotNull();
        }
    }

    @Nested
    @SpringJUnitConfig(classes = UaaStatsdConfiguration.class)
    @TestPropertySource(properties = "statsd.enabled=baz")
    class WithStatsdExplicitlyDisabled {
        @Test
        void statsdIsNotAvailable(@Autowired(required = false) UaaMetricsEmitter statsDClientWrapper) {
            assertThat(statsDClientWrapper).as("statsDClientWrapper must not be available").isNull();
        }
    }

    @Nested
    @SpringJUnitConfig(classes = UaaStatsdConfiguration.class)
    class WithStatsdDisabledByDefault {
        @Test
        void statsdIsNotAvailable(@Autowired(required = false) UaaMetricsEmitter statsDClientWrapper) {
            assertThat(statsDClientWrapper).as("statsDClientWrapper must not be available").isNull();
        }
    }
}